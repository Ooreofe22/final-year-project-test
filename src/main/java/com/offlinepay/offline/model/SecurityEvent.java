package com.offlinepay.offline.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/** Audit log of every rejected or suspicious token. */
@Entity
@Table(name = "security_events")
@Getter
@Setter
@NoArgsConstructor
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SecurityEventType type;

    private String submittedByUserId;
    private Long payerDeviceId;
    private String paymentId;
    private String detail;
    private Instant createdAt = Instant.now();
}
