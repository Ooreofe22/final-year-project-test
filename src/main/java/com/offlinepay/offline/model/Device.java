package com.offlinepay.offline.model;

import com.offlinepay.model.User;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * A phone registered for offline payments. Its private key never leaves the phone's
 * secure hardware; the bank only ever sees the public key.
 *
 * reservedKobo is the bank's view of the offline wallet: money moved out of the main
 * balance and set aside to back offline payments, minus everything already settled.
 */
@Entity
@Table(name = "devices")
@Getter
@Setter
@NoArgsConstructor
public class Device {

    /** Random 63-bit ID, also used inside certificates, requests and tokens. */
    @Id
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    private User user;

    /** 65-byte uncompressed P-256 point. */
    @Column(nullable = false, length = 65)
    private byte[] publicKey;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private DeviceStatus status = DeviceStatus.ACTIVE;

    @Column(nullable = false)
    private long reservedKobo = 0;

    /** Highest payment counter settled so far - informational; uniqueness is enforced per (device, counter). */
    @Column(nullable = false)
    private long highestCounterSeen = -1;

    private Long currentCertificateSerial;
    private Instant certificateExpiresAt;

    private String frozenReason;
    private Instant frozenAt;

    private String label;

    private Instant createdAt = Instant.now();
    private Instant updatedAt = Instant.now();

    @Version
    private Long version;
}
