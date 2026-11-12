package com.offlinepay.offline.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * A payment token that passed every check and was settled into the ledger.
 *
 * Under the bank-guarantee rule, a validly signed token is always honoured for the
 * receiver, even when it turns out to be a double-spend; the bank then recovers the
 * money from the payer (reserve first, then main balance) and flags the payment.
 */
@Entity
@Table(name = "offline_payments",
        uniqueConstraints = @UniqueConstraint(name = "uk_payment_id", columnNames = "paymentId"),
        indexes = {
                @Index(name = "idx_payer_counter", columnList = "payerDeviceId,counter"),
                @Index(name = "idx_receiver", columnList = "receiverDeviceId")
        })
@Getter
@Setter
@NoArgsConstructor
public class OfflinePayment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** SHA-256 of the signed token header. */
    @Column(nullable = false, length = 64)
    private String paymentId;

    private long payerDeviceId;
    private long receiverDeviceId;
    private String payerUserId;
    private String receiverUserId;
    private String payerName;
    private String receiverName;

    private long amountKobo;
    private long counter;
    private long nonce;
    private long certificateSerial;

    /** Payer's own clock when they signed - untrusted, kept for the record. */
    private Instant signedAt;
    private Instant settledAt = Instant.now();
    private String submittedByUserId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FraudFlag fraudFlag = FraudFlag.NONE;

    /** Kobo recovered from the payer's main balance because the reserve did not cover this payment. */
    private long recoveredFromMainKobo = 0;

    @Column(columnDefinition = "TEXT")
    private String rawToken;
}
