package com.offlinepay.offline.crypto;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

/**
 * ECDSA helpers on the NIST P-256 curve (also called secp256r1 / prime256v1).
 *
 * P-256 is used because Android Keystore supports it in secure hardware, so the
 * phone and this server can use exactly the same algorithm:
 *   - key pairs:   EC, curve secp256r1
 *   - signatures:  SHA256withECDSA, DER-encoded (70-72 bytes)
 *   - public keys on the wire: 65-byte "uncompressed point" (0x04 || X || Y)
 */
public final class EcKeys {

    public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    public static final int RAW_PUBLIC_KEY_LENGTH = 65;

    private static final ECParameterSpec P256 = loadP256Params();

    private EcKeys() {}

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            return gen.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("P-256 not available", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] data) {
        try {
            Signature s = Signature.getInstance(SIGNATURE_ALGORITHM);
            s.initSign(key);
            s.update(data);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Signing failed", e);
        }
    }

    /** Returns false for any bad signature or malformed input - never throws. */
    public static boolean verify(PublicKey key, byte[] data, byte[] signature) {
        try {
            Signature s = Signature.getInstance(SIGNATURE_ALGORITHM);
            s.initVerify(key);
            s.update(data);
            return s.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** 65-byte uncompressed point: 0x04 || X(32) || Y(32). */
    public static byte[] toRaw(PublicKey key) {
        ECPoint w = ((ECPublicKey) key).getW();
        byte[] out = new byte[RAW_PUBLIC_KEY_LENGTH];
        out[0] = 0x04;
        copyFixed(w.getAffineX(), out, 1);
        copyFixed(w.getAffineY(), out, 33);
        return out;
    }

    public static PublicKey fromRaw(byte[] raw) {
        if (raw == null || raw.length != RAW_PUBLIC_KEY_LENGTH || raw[0] != 0x04) {
            throw new IllegalArgumentException("Public key must be a 65-byte uncompressed P-256 point");
        }
        try {
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(raw, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(raw, 33, 65));
            ECPublicKeySpec spec = new ECPublicKeySpec(new ECPoint(x, y), P256);
            return KeyFactory.getInstance("EC").generatePublic(spec);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Not a valid P-256 public key", e);
        }
    }

    /**
     * Accepts what a phone will most likely send: either the raw 65-byte point,
     * or the X.509 encoding Android returns from publicKey.getEncoded().
     * Always returns the raw 65-byte form.
     */
    public static byte[] normalizeToRaw(byte[] encoded) {
        if (encoded == null) throw new IllegalArgumentException("Public key is required");
        if (encoded.length == RAW_PUBLIC_KEY_LENGTH && encoded[0] == 0x04) {
            fromRaw(encoded); // validates it is on the curve
            return encoded;
        }
        try {
            PublicKey key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encoded));
            if (!(key instanceof ECPublicKey ec) || ec.getParams().getCurve().getField().getFieldSize() != 256) {
                throw new IllegalArgumentException("Public key must be on the P-256 curve");
            }
            return toRaw(key);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Unrecognised public key encoding", e);
        }
    }

    public static PrivateKey privateKeyFromPkcs8(byte[] pkcs8) {
        try {
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid PKCS#8 EC private key", e);
        }
    }

    private static void copyFixed(BigInteger value, byte[] out, int offset) {
        byte[] bytes = value.toByteArray();
        int len = Math.min(bytes.length, 32);
        System.arraycopy(bytes, bytes.length - len, out, offset + 32 - len, len);
    }

    private static ECParameterSpec loadP256Params() {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}
