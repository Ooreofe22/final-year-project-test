package com.offlinepay.offline.service;

import com.offlinepay.model.User;
import com.offlinepay.offline.model.*;
import com.offlinepay.offline.protocol.PayerCertificate;
import com.offlinepay.offline.protocol.PaymentToken;
import com.offlinepay.offline.protocol.ProtocolException;
import com.offlinepay.offline.repository.DeviceRepository;
import com.offlinepay.offline.repository.OfflinePaymentRepository;
import com.offlinepay.offline.repository.SecurityEventRepository;
import com.offlinepay.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

/**
 * Turns offline payment tokens into real ledger movements once a phone is back online.
 *
 * For every token, in order:
 *   1. Parse it                                   -> MALFORMED_TOKEN
 *   2. Bank signature on the certificate          -> FORGED_CERTIFICATE
 *   3. Certificate belongs to the claimed payer   -> CERTIFICATE_DEVICE_MISMATCH
 *   4. Payer signature on the token               -> TAMPERED_TOKEN
 *   5. Payer and receiver devices exist           -> UNKNOWN_DEVICE
 *   6. Certificate key matches the registered key -> KEY_MISMATCH
 *   7. Certificate was valid when signed          -> CERTIFICATE_EXPIRED
 *   8. Amount within the certificate's limit      -> OVER_CERTIFICATE_LIMIT
 *   9. Submitter is the payer or the receiver     -> NOT_A_PARTY
 *  10. Same token seen before?                    -> ALREADY_SETTLED (harmless, idempotent)
 *  11. Same counter, different token?             -> DOUBLE_SPEND: settle under guarantee, recover, freeze
 *  12. Reserve too small?                         -> OVERSPEND:    settle under guarantee, recover, freeze
 *  13. Otherwise                                  -> SETTLED
 *
 * Liability rule (bank guarantee): a token that passes checks 1-9 was something the receiver
 * could correctly accept offline, so the receiver is always paid. The bank recovers any shortfall
 * from the payer - first their offline reserve, then their main balance (which may go negative) -
 * and freezes the payer's device.
 */
@Service
public class SettlementService {

    private static final Logger log = LoggerFactory.getLogger(SettlementService.class);

    /** Allow small clock differences between phones when checking certificate expiry. */
    private static final long CLOCK_SKEW_SECONDS = 10 * 60;

    private final BankKeyService bankKeyService;
    private final DeviceRepository deviceRepository;
    private final UserRepository userRepository;
    private final OfflinePaymentRepository paymentRepository;
    private final SecurityEventRepository eventRepository;

    public SettlementService(BankKeyService bankKeyService, DeviceRepository deviceRepository,
                             UserRepository userRepository, OfflinePaymentRepository paymentRepository,
                             SecurityEventRepository eventRepository) {
        this.bankKeyService = bankKeyService;
        this.deviceRepository = deviceRepository;
        this.userRepository = userRepository;
        this.paymentRepository = paymentRepository;
        this.eventRepository = eventRepository;
    }

    @Transactional
    public SettlementResult settle(String rawToken, String submittedByUserId) {
        // 1. Parse
        PaymentToken token;
        try {
            token = PaymentToken.fromBase64Url(rawToken);
        } catch (ProtocolException e) {
            return reject(null, null, SecurityEventType.MALFORMED_TOKEN, submittedByUserId, e.getMessage());
        }
        String paymentId = token.paymentId();
        PayerCertificate cert = token.certificate();

        // 2-4. Cryptographic checks (the same ones the receiver's phone ran offline)
        if (!cert.isSignedBy(bankKeyService.publicKey())) {
            return reject(paymentId, token.payerDeviceId(), SecurityEventType.FORGED_CERTIFICATE, submittedByUserId,
                    "Certificate was not issued by the bank");
        }
        if (cert.deviceId() != token.payerDeviceId()) {
            return reject(paymentId, token.payerDeviceId(), SecurityEventType.CERTIFICATE_DEVICE_MISMATCH,
                    submittedByUserId, "Certificate belongs to a different device");
        }
        if (!token.isSignedByCertifiedPayer()) {
            return reject(paymentId, token.payerDeviceId(), SecurityEventType.TAMPERED_TOKEN, submittedByUserId,
                    "Payer signature does not match the payment details");
        }

        // 5. Devices (read without locks first, just to learn who the two parties are)
        var payerInfo = deviceRepository.findOwner(token.payerDeviceId()).orElse(null);
        var receiverInfo = deviceRepository.findOwner(token.receiverDeviceId()).orElse(null);
        if (payerInfo == null || receiverInfo == null) {
            return reject(paymentId, token.payerDeviceId(), SecurityEventType.UNKNOWN_DEVICE, submittedByUserId,
                    payerInfo == null ? "Unknown payer device" : "Unknown receiver device");
        }

        // 6-8. Certificate consistency
        if (!Arrays.equals(cert.publicKey(), payerInfo.getPublicKey())) {
            return reject(paymentId, token.payerDeviceId(), SecurityEventType.KEY_MISMATCH, submittedByUserId,
                    "Certificate key does not match the registered device key");
        }
        if (token.timestamp() > cert.expiresAt() + CLOCK_SKEW_SECONDS) {
            return reject(paymentId, token.payerDeviceId(), SecurityEventType.CERTIFICATE_EXPIRED, submittedByUserId,
                    "Payment was signed after the payer's certificate expired");
        }
        if (token.amountKobo() <= 0 || token.amountKobo() > cert.limitKobo()) {
            return reject(paymentId, token.payerDeviceId(), SecurityEventType.OVER_CERTIFICATE_LIMIT,
                    submittedByUserId, "Amount exceeds what the certificate allows");
        }

        String payerUserId = payerInfo.getUserId();
        String receiverUserId = receiverInfo.getUserId();

        // 9. Only the two parties may submit a payment
        if (!submittedByUserId.equals(payerUserId) && !submittedByUserId.equals(receiverUserId)) {
            return reject(paymentId, token.payerDeviceId(), SecurityEventType.NOT_A_PARTY, submittedByUserId,
                    "Only the payer or the receiver can submit this payment");
        }

        // Lock order is always: users (sorted by id), then the payer's device. OfflineWalletService
        // locks user then device too, so the two can never deadlock each other.
        User payer;
        User receiver;
        if (payerUserId.compareTo(receiverUserId) <= 0) {
            payer = userRepository.findByIdForUpdate(payerUserId).orElseThrow();
            receiver = payerUserId.equals(receiverUserId) ? payer : userRepository.findByIdForUpdate(receiverUserId).orElseThrow();
        } else {
            receiver = userRepository.findByIdForUpdate(receiverUserId).orElseThrow();
            payer = userRepository.findByIdForUpdate(payerUserId).orElseThrow();
        }
        Device payerDevice = deviceRepository.findByIdForUpdate(token.payerDeviceId()).orElseThrow();

        // 10. Idempotency (checked under the locks, so two simultaneous syncs cannot both settle)
        var existing = paymentRepository.findByPaymentId(paymentId);
        if (existing.isPresent()) {
            OfflinePayment p = existing.get();
            return new SettlementResult(paymentId, SettlementResult.Status.ALREADY_SETTLED, null, p.getFraudFlag(),
                    Money.toNaira(p.getAmountKobo()), p.getPayerName(), p.getReceiverName(), "Already settled");
        }

        // 11-12. Fraud checks
        boolean counterReused = !paymentRepository
                .findByPayerDeviceIdAndCounter(token.payerDeviceId(), token.counter()).isEmpty();
        boolean overspend = payerDevice.getReservedKobo() < token.amountKobo();
        FraudFlag flag = counterReused ? FraudFlag.DOUBLE_SPEND : overspend ? FraudFlag.OVERSPEND : FraudFlag.NONE;

        // Move the money: from the reserve first, any shortfall from the payer's main balance
        long amount = token.amountKobo();
        long fromReserve = Math.min(payerDevice.getReservedKobo(), amount);
        long fromMain = amount - fromReserve;
        payerDevice.setReservedKobo(payerDevice.getReservedKobo() - fromReserve);
        payerDevice.setHighestCounterSeen(Math.max(payerDevice.getHighestCounterSeen(), token.counter()));
        payerDevice.setUpdatedAt(Instant.now());
        if (fromMain > 0) {
            payer.setBalance(Money.toNaira(Money.toKobo(payer.getBalance()) - fromMain));
            payer.setUpdatedAt(Instant.now());
        }
        receiver.setBalance(Money.toNaira(Money.toKobo(receiver.getBalance()) + amount));
        receiver.setUpdatedAt(Instant.now());

        if (flag != FraudFlag.NONE) {
            payerDevice.setStatus(DeviceStatus.FROZEN);
            payerDevice.setFrozenAt(Instant.now());
            payerDevice.setFrozenReason(flag == FraudFlag.DOUBLE_SPEND
                    ? "Double-spend: counter " + token.counter() + " used for two different payments"
                    : "Overspend: offline payments exceeded the reserved amount");
            recordEvent(flag == FraudFlag.DOUBLE_SPEND ? SecurityEventType.DOUBLE_SPEND_DETECTED
                            : SecurityEventType.OVERSPEND_DETECTED,
                    paymentId, token.payerDeviceId(), submittedByUserId,
                    payerDevice.getFrozenReason() + " (recovered ₦" + Money.toNaira(fromMain) + " from main balance)");
            log.warn("Fraud flag {} on device {} - device frozen", flag, payerDevice.getId());
        }

        OfflinePayment payment = new OfflinePayment();
        payment.setPaymentId(paymentId);
        payment.setPayerDeviceId(token.payerDeviceId());
        payment.setReceiverDeviceId(token.receiverDeviceId());
        payment.setPayerUserId(payerUserId);
        payment.setReceiverUserId(receiverUserId);
        payment.setPayerName(payer.getDisplayName());
        payment.setReceiverName(receiver.getDisplayName());
        payment.setAmountKobo(amount);
        payment.setCounter(token.counter());
        payment.setNonce(token.nonce());
        payment.setCertificateSerial(cert.serial());
        payment.setSignedAt(Instant.ofEpochSecond(token.timestamp()));
        payment.setSubmittedByUserId(submittedByUserId);
        payment.setFraudFlag(flag);
        payment.setRecoveredFromMainKobo(fromMain);
        payment.setRawToken(rawToken.trim());

        userRepository.save(payer);
        if (receiver != payer) userRepository.save(receiver);
        deviceRepository.save(payerDevice);
        paymentRepository.save(payment);

        String message = switch (flag) {
            case NONE -> "Settled";
            case DOUBLE_SPEND -> "Settled under bank guarantee - payer double-spent and has been frozen";
            case OVERSPEND -> "Settled under bank guarantee - payer overspent and has been frozen";
        };
        return new SettlementResult(paymentId, SettlementResult.Status.SETTLED, null, flag,
                Money.toNaira(amount), payer.getDisplayName(), receiver.getDisplayName(), message);
    }

    public List<OfflinePayment> paymentsFor(String userId) {
        return paymentRepository.findByPayerUserIdOrReceiverUserIdOrderBySettledAtDesc(userId, userId);
    }

    private SettlementResult reject(String paymentId, Long payerDeviceId, SecurityEventType type,
                                    String submittedBy, String message) {
        recordEvent(type, paymentId, payerDeviceId, submittedBy, message);
        return SettlementResult.rejected(paymentId, type, message);
    }

    private void recordEvent(SecurityEventType type, String paymentId, Long payerDeviceId,
                             String submittedBy, String detail) {
        SecurityEvent event = new SecurityEvent();
        event.setType(type);
        event.setPaymentId(paymentId);
        event.setPayerDeviceId(payerDeviceId);
        event.setSubmittedByUserId(submittedBy);
        event.setDetail(detail);
        eventRepository.save(event);
    }
}
