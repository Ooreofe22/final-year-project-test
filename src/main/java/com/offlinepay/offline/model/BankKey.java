package com.offlinepay.offline.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * The bank's certificate-signing key, generated once and kept so that certificates
 * remain valid across restarts. A real bank would keep this in an HSM, never in a table.
 */
@Entity
@Table(name = "bank_keys")
@Getter
@Setter
@NoArgsConstructor
public class BankKey {

    @Id
    private String id = "primary";

    // Plain binary column (bytea on PostgreSQL) - not @Lob, which PostgreSQL stores as a large object
    @Column(nullable = false, length = 512)
    private byte[] privateKeyPkcs8;

    @Column(nullable = false, length = 65)
    private byte[] publicKeyRaw;

    private Instant createdAt = Instant.now();
}
