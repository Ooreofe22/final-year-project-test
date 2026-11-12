package com.offlinepay.offline.service;

import com.offlinepay.model.User;
import com.offlinepay.model.UserStatus;
import com.offlinepay.offline.crypto.EcKeys;
import com.offlinepay.offline.model.Device;
import com.offlinepay.offline.model.DeviceStatus;
import com.offlinepay.offline.protocol.PayerCertificate;
import com.offlinepay.offline.repository.DeviceRepository;
import com.offlinepay.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Everything the phone does with the bank while ONLINE:
 * register its key, load/unload the offline wallet, and renew its certificate.
 */
@Service
public class OfflineWalletService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final DeviceRepository deviceRepository;
    private final UserRepository userRepository;
    private final BankKeyService bankKeyService;
    private final long walletLimitKobo;
    private final int certificateValidityDays;

    public OfflineWalletService(DeviceRepository deviceRepository, UserRepository userRepository,
                                BankKeyService bankKeyService,
                                @Value("${offline.wallet-limit:20000}") BigDecimal walletLimitNaira,
                                @Value("${offline.certificate-validity-days:7}") int certificateValidityDays) {
        this.deviceRepository = deviceRepository;
        this.userRepository = userRepository;
        this.bankKeyService = bankKeyService;
        this.walletLimitKobo = Money.toKobo(walletLimitNaira);
        this.certificateValidityDays = certificateValidityDays;
    }

    public long walletLimitKobo() {
        return walletLimitKobo;
    }

    /**
     * Registers the phone's public key. One active device per user: a new registration
     * revokes the old one, but only once its offline wallet is empty, so reserved money
     * is never stranded on a lost key.
     */
    @Transactional
    public Device registerDevice(String userId, byte[] publicKey, String label) {
        User user = activeUser(userId);
        byte[] raw = EcKeys.normalizeToRaw(publicKey);

        deviceRepository.findFirstByUserAndStatusInOrderByCreatedAtDesc(user,
                List.of(DeviceStatus.ACTIVE, DeviceStatus.FROZEN)).ifPresent(existing -> {
            if (existing.getStatus() == DeviceStatus.FROZEN) {
                throw new IllegalStateException("Your current device is frozen for review - contact support");
            }
            if (existing.getReservedKobo() > 0) {
                throw new IllegalStateException("Unload your offline wallet on your current device first");
            }
            existing.setStatus(DeviceStatus.REVOKED);
            existing.setUpdatedAt(Instant.now());
            deviceRepository.save(existing);
        });

        Device device = new Device();
        device.setId(newDeviceId());
        device.setUser(user);
        device.setPublicKey(raw);
        device.setLabel(label);
        return deviceRepository.save(device);
    }

    public Device currentDevice(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Account not found"));
        return deviceRepository.findFirstByUserAndStatusInOrderByCreatedAtDesc(user,
                        List.of(DeviceStatus.ACTIVE, DeviceStatus.FROZEN))
                .orElseThrow(() -> new IllegalStateException("No device registered - register this phone first"));
    }

    /** Moves money from the main balance into the offline wallet and issues a fresh certificate. */
    @Transactional
    public LoadResult load(String userId, BigDecimal amountNaira) {
        long amount = positiveKobo(amountNaira);
        User user = userRepository.findByIdForUpdate(userId)
                .orElseThrow(() -> new IllegalArgumentException("Account not found"));
        requireActive(user);
        Device device = lockedActiveDevice(user);

        if (device.getReservedKobo() + amount > walletLimitKobo) {
            throw new IllegalStateException("Offline wallet limit is ₦" + Money.toNaira(walletLimitKobo)
                    + " - you can add at most ₦" + Money.toNaira(walletLimitKobo - device.getReservedKobo()));
        }
        long mainBalance = Money.toKobo(user.getBalance());
        if (mainBalance < amount) {
            throw new IllegalStateException("Insufficient balance");
        }

        user.setBalance(Money.toNaira(mainBalance - amount));
        user.setUpdatedAt(Instant.now());
        device.setReservedKobo(device.getReservedKobo() + amount);
        PayerCertificate cert = issueCertificate(user, device);
        userRepository.save(user);
        deviceRepository.save(device);
        return new LoadResult(device, user.getBalance(), cert);
    }

    /**
     * Moves unspent offline money back to the main balance.
     * The phone must sync all its outgoing payments first; if it later turns out it had
     * spent more than it claimed, settlement recovers the difference from the main balance
     * and freezes the device (see SettlementService).
     */
    @Transactional
    public LoadResult unload(String userId, BigDecimal amountNaira) {
        long amount = positiveKobo(amountNaira);
        User user = userRepository.findByIdForUpdate(userId)
                .orElseThrow(() -> new IllegalArgumentException("Account not found"));
        requireActive(user);
        Device device = lockedActiveDevice(user);

        if (amount > device.getReservedKobo()) {
            throw new IllegalStateException("Only ₦" + Money.toNaira(device.getReservedKobo()) + " is in your offline wallet");
        }
        device.setReservedKobo(device.getReservedKobo() - amount);
        user.setBalance(Money.toNaira(Money.toKobo(user.getBalance()) + amount));
        user.setUpdatedAt(Instant.now());

        PayerCertificate cert = device.getReservedKobo() > 0 ? issueCertificate(user, device) : null;
        if (cert == null) {
            device.setCurrentCertificateSerial(null);
            device.setCertificateExpiresAt(null);
            device.setUpdatedAt(Instant.now());
        }
        userRepository.save(user);
        deviceRepository.save(device);
        return new LoadResult(device, user.getBalance(), cert);
    }

    /** Re-issues the certificate with a fresh expiry date. */
    @Transactional
    public PayerCertificate renewCertificate(String userId) {
        User user = activeUser(userId);
        Device device = lockedActiveDevice(user);
        if (device.getReservedKobo() <= 0) {
            throw new IllegalStateException("Load your offline wallet first");
        }
        PayerCertificate cert = issueCertificate(user, device);
        deviceRepository.save(device);
        return cert;
    }

    /**
     * The certificate's limit equals what the bank actually holds for this device, so a
     * receiver can refuse any single payment larger than the money backing it.
     */
    private PayerCertificate issueCertificate(User user, Device device) {
        Instant now = Instant.now();
        Instant expires = now.plus(certificateValidityDays, ChronoUnit.DAYS);
        long serial = Math.abs(RANDOM.nextLong());
        PayerCertificate cert = PayerCertificate.issue(serial, device.getId(), device.getPublicKey(),
                device.getReservedKobo(), now.getEpochSecond(), expires.getEpochSecond(),
                user.getDisplayName(), bankKeyService.privateKey());
        device.setCurrentCertificateSerial(serial);
        device.setCertificateExpiresAt(expires);
        device.setUpdatedAt(now);
        return cert;
    }

    private Device lockedActiveDevice(User user) {
        Device device = deviceRepository.findCurrentForUpdate(user, List.of(DeviceStatus.ACTIVE, DeviceStatus.FROZEN))
                .stream().findFirst()
                .orElseThrow(() -> new IllegalStateException("No device registered - register this phone first"));
        if (device.getStatus() == DeviceStatus.FROZEN) {
            throw new IllegalStateException("This device is frozen for review: " + device.getFrozenReason());
        }
        return device;
    }

    private User activeUser(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Account not found"));
        requireActive(user);
        return user;
    }

    private static void requireActive(User user) {
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new IllegalStateException("Account is not active");
        }
    }

    private static long positiveKobo(BigDecimal naira) {
        long kobo;
        try {
            kobo = Money.toKobo(naira);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("Amount can have at most 2 decimal places");
        }
        if (kobo <= 0) throw new IllegalArgumentException("Amount must be positive");
        return kobo;
    }

    private long newDeviceId() {
        long id;
        do {
            id = RANDOM.nextLong() & Long.MAX_VALUE;
        } while (id == 0 || deviceRepository.existsById(id));
        return id;
    }

    public record LoadResult(Device device, BigDecimal mainBalance, PayerCertificate certificate) {}
}
