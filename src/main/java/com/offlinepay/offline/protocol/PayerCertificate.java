package com.offlinepay.offline.protocol;

import com.offlinepay.offline.crypto.EcKeys;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Issued and signed by the bank when a user loads their offline wallet.
 * It tells any receiver, without contacting the bank:
 *   "Device {deviceId}, owned by {displayName}, holds signing key {publicKey}
 *    and may pay up to {limitKobo} kobo until {expiresAt}."
 *
 * Byte layout (big-endian):
 *   u8   type = 'C' (0x43)
 *   u8   version = 1
 *   i64  serial            - unique per certificate
 *   i64  deviceId
 *   65   publicKey         - uncompressed P-256 point
 *   i64  limitKobo         - amount the bank has reserved for offline use
 *   i64  issuedAt          - epoch seconds
 *   i64  expiresAt         - epoch seconds
 *   u8+n displayName       - UTF-8, max 60 bytes
 *   ---- everything above is signed by the bank ----
 *   u8+n bankSignature     - DER ECDSA, SHA256withECDSA
 */
public record PayerCertificate(
        long serial,
        long deviceId,
        byte[] publicKey,
        long limitKobo,
        long issuedAt,
        long expiresAt,
        String displayName,
        byte[] bankSignature) {

    public static final int TYPE = 'C';
    public static final int VERSION = 1;

    public static PayerCertificate issue(long serial, long deviceId, byte[] publicKey, long limitKobo,
                                         long issuedAt, long expiresAt, String displayName,
                                         PrivateKey bankKey) {
        String name = truncateUtf8(displayName, 60);
        PayerCertificate unsigned = new PayerCertificate(serial, deviceId, publicKey, limitKobo,
                issuedAt, expiresAt, name, new byte[0]);
        byte[] signature = EcKeys.sign(bankKey, unsigned.signedBytes());
        return new PayerCertificate(serial, deviceId, publicKey, limitKobo, issuedAt, expiresAt, name, signature);
    }

    /** The exact bytes covered by the bank's signature. */
    public byte[] signedBytes() {
        return new Bytes.Writer()
                .u8(TYPE).u8(VERSION)
                .i64(serial).i64(deviceId)
                .raw(publicKey)
                .i64(limitKobo).i64(issuedAt).i64(expiresAt)
                .text8(displayName)
                .toBytes();
    }

    public byte[] encode() {
        return new Bytes.Writer().raw(signedBytes()).short8(bankSignature).toBytes();
    }

    public String toBase64Url() {
        return Bytes.toBase64Url(encode());
    }

    public static PayerCertificate decode(byte[] data) {
        Bytes.Reader r = new Bytes.Reader(data);
        PayerCertificate c = read(r);
        r.expectEnd();
        return c;
    }

    public static PayerCertificate fromBase64Url(String text) {
        return decode(Bytes.fromBase64Url(text));
    }

    static PayerCertificate read(Bytes.Reader r) {
        if (r.u8() != TYPE) throw new ProtocolException("Not a payer certificate");
        if (r.u8() != VERSION) throw new ProtocolException("Unsupported certificate version");
        long serial = r.i64();
        long deviceId = r.i64();
        byte[] publicKey = r.raw(EcKeys.RAW_PUBLIC_KEY_LENGTH);
        long limit = r.i64();
        long issuedAt = r.i64();
        long expiresAt = r.i64();
        String name = r.text8();
        byte[] signature = r.short8();
        return new PayerCertificate(serial, deviceId, publicKey, limit, issuedAt, expiresAt, name, signature);
    }

    /** Check 1 of offline verification: did the bank really issue this? */
    public boolean isSignedBy(PublicKey bankPublicKey) {
        return EcKeys.verify(bankPublicKey, signedBytes(), bankSignature);
    }

    public PublicKey payerPublicKey() {
        return EcKeys.fromRaw(publicKey);
    }

    public boolean isExpiredAt(long epochSeconds) {
        return epochSeconds > expiresAt;
    }

    private static String truncateUtf8(String s, int maxBytes) {
        if (s == null) return "";
        String t = s;
        while (t.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > maxBytes) {
            t = t.substring(0, t.length() - 1);
        }
        return t;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof PayerCertificate other && Arrays.equals(encode(), other.encode());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encode());
    }
}
