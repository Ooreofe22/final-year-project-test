package com.offlinepay.offline.web;

import com.offlinepay.model.User;
import com.offlinepay.offline.model.Device;
import com.offlinepay.offline.model.OfflinePayment;
import com.offlinepay.offline.protocol.PayerCertificate;
import com.offlinepay.offline.service.*;
import com.offlinepay.repository.UserRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/offline")
public class OfflineController {

    private static final int MAX_TOKENS_PER_SYNC = 100;

    private final OfflineWalletService walletService;
    private final SettlementService settlementService;
    private final BankKeyService bankKeyService;
    private final UserRepository userRepository;

    public OfflineController(OfflineWalletService walletService, SettlementService settlementService,
                             BankKeyService bankKeyService, UserRepository userRepository) {
        this.walletService = walletService;
        this.settlementService = settlementService;
        this.bankKeyService = bankKeyService;
        this.userRepository = userRepository;
    }

    /** Public: the key every phone needs to check certificates offline. Ship it inside the app. */
    @GetMapping("/bank-public-key")
    public Map<String, Object> bankPublicKey() {
        return Map.of(
                "algorithm", "ECDSA P-256 (secp256r1), SHA256withECDSA",
                "publicKeyRaw", bankKeyService.publicKeyRawBase64(),
                "publicKeyX509", bankKeyService.publicKeyX509Base64());
    }

    /** Registers this phone's hardware-backed public key. */
    @PostMapping("/devices")
    public ResponseEntity<?> registerDevice(@RequestBody RegisterDeviceRequest request, Authentication auth) {
        byte[] key;
        try {
            key = Base64.getDecoder().decode(request.publicKey());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new IllegalArgumentException("publicKey must be standard base64");
        }
        Device device = walletService.registerDevice(userId(auth), key, request.label());
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "deviceId", String.valueOf(device.getId()),
                "status", device.getStatus().name(),
                "walletLimit", Money.toNaira(walletService.walletLimitKobo())));
    }

    /** Main balance, offline wallet and current certificate in one call - the Home screen. */
    @GetMapping("/wallet")
    public WalletView wallet(Authentication auth) {
        String id = userId(auth);
        User user = userRepository.findById(id).orElseThrow();
        Device device = walletService.currentDevice(id);
        return WalletView.of(user.getBalance(), device, null, walletService.walletLimitKobo());
    }

    @PostMapping("/wallet/load")
    public WalletView load(@RequestBody AmountRequest request, Authentication auth) {
        var result = walletService.load(userId(auth), request.amount());
        return WalletView.of(result.mainBalance(), result.device(), result.certificate(), walletService.walletLimitKobo());
    }

    @PostMapping("/wallet/unload")
    public WalletView unload(@RequestBody AmountRequest request, Authentication auth) {
        var result = walletService.unload(userId(auth), request.amount());
        return WalletView.of(result.mainBalance(), result.device(), result.certificate(), walletService.walletLimitKobo());
    }

    @PostMapping("/wallet/certificate")
    public Map<String, Object> renewCertificate(Authentication auth) {
        PayerCertificate cert = walletService.renewCertificate(userId(auth));
        return Map.of(
                "certificate", cert.toBase64Url(),
                "expiresAt", Instant.ofEpochSecond(cert.expiresAt()).toString(),
                "limit", Money.toNaira(cert.limitKobo()));
    }

    /**
     * Uploads tokens collected offline - both payments made and payments received.
     * Each token settles independently; one bad token never blocks the others.
     */
    @PostMapping("/sync")
    public ResponseEntity<?> sync(@RequestBody SyncRequest request, Authentication auth) {
        if (request.tokens() == null || request.tokens().isEmpty()) {
            throw new IllegalArgumentException("tokens must not be empty");
        }
        if (request.tokens().size() > MAX_TOKENS_PER_SYNC) {
            throw new IllegalArgumentException("At most " + MAX_TOKENS_PER_SYNC + " tokens per sync");
        }
        String id = userId(auth);
        List<SettlementResult> results = new ArrayList<>();
        for (String token : request.tokens()) {
            results.add(settleOnce(token, id));
        }
        long settled = results.stream().filter(r -> r.status() == SettlementResult.Status.SETTLED).count();
        long rejected = results.stream().filter(r -> r.status() == SettlementResult.Status.REJECTED).count();
        return ResponseEntity.ok(Map.of("settled", settled, "rejected", rejected, "results", results));
    }

    @GetMapping("/payments")
    public List<PaymentView> payments(Authentication auth) {
        String id = userId(auth);
        return settlementService.paymentsFor(id).stream().map(p -> PaymentView.from(p, id)).toList();
    }

    /** If payer and receiver sync the same token at the same moment, one hits the unique key - retry once. */
    private SettlementResult settleOnce(String token, String userId) {
        try {
            return settlementService.settle(token, userId);
        } catch (DataIntegrityViolationException e) {
            return settlementService.settle(token, userId);
        }
    }

    private static String userId(Authentication auth) {
        return ((User) auth.getPrincipal()).getId();
    }

    // ---- request / response bodies ----

    public record RegisterDeviceRequest(String publicKey, String label) {}

    public record AmountRequest(BigDecimal amount) {}

    public record SyncRequest(List<String> tokens) {}

    public record WalletView(BigDecimal mainBalance, String deviceId, String deviceStatus, String frozenReason,
                             BigDecimal offlineReserved, BigDecimal offlineLimit, String certificate,
                             String certificateExpiresAt) {
        static WalletView of(BigDecimal main, Device d, PayerCertificate cert, long limitKobo) {
            return new WalletView(main, String.valueOf(d.getId()), d.getStatus().name(), d.getFrozenReason(),
                    Money.toNaira(d.getReservedKobo()), Money.toNaira(limitKobo),
                    cert == null ? null : cert.toBase64Url(),
                    d.getCertificateExpiresAt() == null ? null : d.getCertificateExpiresAt().toString());
        }
    }

    public record PaymentView(String paymentId, String direction, BigDecimal amount, String counterparty,
                              long counter, String fraudFlag, String signedAt, String settledAt) {
        static PaymentView from(OfflinePayment p, String me) {
            boolean outgoing = me.equals(p.getPayerUserId());
            return new PaymentView(p.getPaymentId(), outgoing ? "SENT" : "RECEIVED", Money.toNaira(p.getAmountKobo()),
                    outgoing ? p.getReceiverName() : p.getPayerName(), p.getCounter(), p.getFraudFlag().name(),
                    p.getSignedAt().toString(), p.getSettledAt().toString());
        }
    }
}
