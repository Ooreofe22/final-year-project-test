package com.offlinepay.admin;

import com.offlinepay.model.User;
import com.offlinepay.model.UserStatus;
import com.offlinepay.offline.model.*;
import com.offlinepay.offline.repository.DeviceRepository;
import com.offlinepay.offline.repository.OfflinePaymentRepository;
import com.offlinepay.offline.repository.SecurityEventRepository;
import com.offlinepay.offline.service.Money;
import com.offlinepay.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Bank dashboard endpoints - what you project during the defence.
 * Gated by a shared X-Admin-Key header: fine for a demo, NOT production-grade auth.
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    private final UserRepository userRepository;
    private final DeviceRepository deviceRepository;
    private final OfflinePaymentRepository paymentRepository;
    private final SecurityEventRepository eventRepository;

    @Value("${admin.api-key:changeme-admin-key}")
    private String adminApiKey;

    public AdminController(UserRepository userRepository, DeviceRepository deviceRepository,
                           OfflinePaymentRepository paymentRepository, SecurityEventRepository eventRepository) {
        this.userRepository = userRepository;
        this.deviceRepository = deviceRepository;
        this.paymentRepository = paymentRepository;
        this.eventRepository = eventRepository;
    }

    @GetMapping("/stats")
    public ResponseEntity<?> stats(@RequestHeader("X-Admin-Key") String key) {
        if (!checkKey(key)) return unauthorized();
        Map<String, Long> attacks = new LinkedHashMap<>();
        Arrays.stream(SecurityEventType.values()).forEach(t -> attacks.put(t.name(), eventRepository.countByType(t)));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("users", userRepository.count());
        body.put("devices", deviceRepository.count());
        body.put("frozenDevices", deviceRepository.findByStatusOrderByUpdatedAtDesc(DeviceStatus.FROZEN).size());
        body.put("settledPayments", paymentRepository.count());
        body.put("settledVolume", Money.toNaira(paymentRepository.totalVolumeKobo()));
        body.put("doubleSpends", paymentRepository.countByFraudFlag(FraudFlag.DOUBLE_SPEND));
        body.put("overspends", paymentRepository.countByFraudFlag(FraudFlag.OVERSPEND));
        body.put("securityEventsByType", attacks);
        return ResponseEntity.ok(body);
    }

    @GetMapping("/accounts")
    @Transactional(readOnly = true)
    public ResponseEntity<?> accounts(@RequestHeader("X-Admin-Key") String key) {
        if (!checkKey(key)) return unauthorized();
        return ResponseEntity.ok(userRepository.findAllByOrderByCreatedAtDesc().stream().map(AccountView::from).toList());
    }

    @PostMapping("/accounts/{id}/suspend")
    public ResponseEntity<?> suspend(@PathVariable String id, @RequestHeader("X-Admin-Key") String key) {
        return setStatus(id, key, UserStatus.SUSPENDED);
    }

    @PostMapping("/accounts/{id}/reactivate")
    public ResponseEntity<?> reactivate(@PathVariable String id, @RequestHeader("X-Admin-Key") String key) {
        return setStatus(id, key, UserStatus.ACTIVE);
    }

    @GetMapping("/devices")
    @Transactional(readOnly = true)
    public ResponseEntity<?> devices(@RequestHeader("X-Admin-Key") String key) {
        if (!checkKey(key)) return unauthorized();
        return ResponseEntity.ok(deviceRepository.findAllByOrderByCreatedAtDesc().stream().map(DeviceView::from).toList());
    }

    /** Lift a fraud freeze after review (e.g. the double-spend was a genuine app bug). */
    @PostMapping("/devices/{id}/unfreeze")
    @Transactional
    public ResponseEntity<?> unfreeze(@PathVariable Long id, @RequestHeader("X-Admin-Key") String key) {
        if (!checkKey(key)) return unauthorized();
        Device d = deviceRepository.findByIdForUpdate(id).orElseThrow(() -> new IllegalArgumentException("Device not found"));
        if (d.getStatus() != DeviceStatus.FROZEN) throw new IllegalStateException("Device is not frozen");
        d.setStatus(DeviceStatus.ACTIVE);
        d.setFrozenReason(null);
        d.setFrozenAt(null);
        d.setUpdatedAt(Instant.now());
        deviceRepository.save(d);
        return ResponseEntity.ok(Map.of("deviceId", String.valueOf(id), "status", "ACTIVE"));
    }

    @GetMapping("/payments")
    public ResponseEntity<?> payments(@RequestHeader("X-Admin-Key") String key) {
        if (!checkKey(key)) return unauthorized();
        return ResponseEntity.ok(paymentRepository.findAllByOrderBySettledAtDesc().stream().map(PaymentView::from).toList());
    }

    @GetMapping("/payments/flagged")
    public ResponseEntity<?> flagged(@RequestHeader("X-Admin-Key") String key) {
        if (!checkKey(key)) return unauthorized();
        return ResponseEntity.ok(paymentRepository.findByFraudFlagNotOrderBySettledAtDesc(FraudFlag.NONE).stream()
                .map(PaymentView::from).toList());
    }

    @GetMapping("/security-events")
    public ResponseEntity<?> securityEvents(@RequestHeader("X-Admin-Key") String key) {
        if (!checkKey(key)) return unauthorized();
        return ResponseEntity.ok(eventRepository.findAllByOrderByCreatedAtDesc());
    }

    private ResponseEntity<?> setStatus(String id, String key, UserStatus status) {
        if (!checkKey(key)) return unauthorized();
        User user = userRepository.findById(id).orElseThrow(() -> new IllegalArgumentException("Account not found"));
        user.setStatus(status);
        userRepository.save(user);
        return ResponseEntity.ok(Map.of("id", id, "status", status.name()));
    }

    private boolean checkKey(String provided) {
        return adminApiKey.equals(provided);
    }

    private ResponseEntity<?> unauthorized() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Invalid admin key"));
    }

    public record AccountView(String id, String email, String displayName, BigDecimal balance, String status,
                              Instant createdAt) {
        static AccountView from(User u) {
            return new AccountView(u.getId(), u.getEmail(), u.getDisplayName(), u.getBalance(), u.getStatus().name(),
                    u.getCreatedAt());
        }
    }

    public record DeviceView(String deviceId, String userEmail, String displayName, String status,
                             BigDecimal offlineReserved, long highestCounterSeen, String frozenReason,
                             Instant certificateExpiresAt, Instant createdAt) {
        static DeviceView from(Device d) {
            return new DeviceView(String.valueOf(d.getId()), d.getUser().getEmail(), d.getUser().getDisplayName(),
                    d.getStatus().name(), Money.toNaira(d.getReservedKobo()), d.getHighestCounterSeen(),
                    d.getFrozenReason(), d.getCertificateExpiresAt(), d.getCreatedAt());
        }
    }

    public record PaymentView(String paymentId, String payer, String receiver, BigDecimal amount, long counter,
                              String fraudFlag, BigDecimal recoveredFromMain, Instant signedAt, Instant settledAt) {
        static PaymentView from(OfflinePayment p) {
            return new PaymentView(p.getPaymentId(), p.getPayerName(), p.getReceiverName(),
                    Money.toNaira(p.getAmountKobo()), p.getCounter(), p.getFraudFlag().name(),
                    Money.toNaira(p.getRecoveredFromMainKobo()), p.getSignedAt(), p.getSettledAt());
        }
    }
}
