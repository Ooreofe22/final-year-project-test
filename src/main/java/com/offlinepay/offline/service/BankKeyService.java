package com.offlinepay.offline.service;

import com.offlinepay.offline.crypto.EcKeys;
import com.offlinepay.offline.model.BankKey;
import com.offlinepay.offline.repository.BankKeyRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Holds the bank's ECDSA key pair. The private key signs payer certificates; the
 * public key is baked into every copy of the app so phones can check certificates offline.
 */
@Service
public class BankKeyService {

    private static final Logger log = LoggerFactory.getLogger(BankKeyService.class);

    private final BankKeyRepository repository;
    private final String configuredPrivateKey;
    private final String configuredPublicKey;

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private byte[] publicKeyRaw;

    public BankKeyService(BankKeyRepository repository,
                          @Value("${offline.bank-private-key:}") String configuredPrivateKey,
                          @Value("${offline.bank-public-key:}") String configuredPublicKey) {
        this.repository = repository;
        this.configuredPrivateKey = configuredPrivateKey;
        this.configuredPublicKey = configuredPublicKey;
    }

    @PostConstruct
    public void init() {
        if (!configuredPrivateKey.isBlank() && !configuredPublicKey.isBlank()) {
            privateKey = EcKeys.privateKeyFromPkcs8(Base64.getDecoder().decode(configuredPrivateKey));
            publicKeyRaw = EcKeys.normalizeToRaw(Base64.getDecoder().decode(configuredPublicKey));
            publicKey = EcKeys.fromRaw(publicKeyRaw);
            log.info("Bank signing key loaded from configuration");
            return;
        }

        BankKey stored = repository.findById("primary").orElseGet(() -> {
            KeyPair pair = EcKeys.generateKeyPair();
            BankKey k = new BankKey();
            k.setPrivateKeyPkcs8(pair.getPrivate().getEncoded());
            k.setPublicKeyRaw(EcKeys.toRaw(pair.getPublic()));
            log.warn("Generated a new bank signing key. Phones must download the new public key from /offline/bank-public-key");
            return repository.save(k);
        });
        privateKey = EcKeys.privateKeyFromPkcs8(stored.getPrivateKeyPkcs8());
        publicKeyRaw = stored.getPublicKeyRaw();
        publicKey = EcKeys.fromRaw(publicKeyRaw);
    }

    PrivateKey privateKey() {
        return privateKey;
    }

    public PublicKey publicKey() {
        return publicKey;
    }

    public byte[] publicKeyRaw() {
        return publicKeyRaw.clone();
    }

    public String publicKeyRawBase64() {
        return Base64.getEncoder().encodeToString(publicKeyRaw);
    }

    public String publicKeyX509Base64() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}
