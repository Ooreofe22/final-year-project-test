package com.offlinepay.offline.protocol;

import com.offlinepay.offline.crypto.EcKeys;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Scan 2 - shown as a QR code on the PAYER's phone after they confirm with PIN or fingerprint.
 * This IS the money: a payment signed by the payer's hardware-held key, carrying the
 * bank-signed certificate that proves the key is legitimate.
 *
 * Byte layout (big-endian):
 *   u8   type = 'P' (0x50)
 *   u8   version = 1
 *   i64  payerDeviceId
 *   i64  receiverDeviceId  - locks the token to one receiver (stops interception)
 *   i64  amountKobo
 *   i64  counter           - +1 on every payment from this device (exposes copies / double-spends)
 *   i64  timestamp         - epoch seconds, payer's clock
 *   i64  nonce             - copied from the receiver's request (stops replay)
 *   ---- the bytes above ("header") are signed by the payer ----
 *   u16+n certificate      - the payer's PayerCertificate
 *   u8+n payerSignature    - DER ECDSA over the header
 */
public record PaymentToken(
        long payerDeviceId,
        long receiverDeviceId,
        long amountKobo,
        long counter,
        long timestamp,
        long nonce,
        PayerCertificate certificate,
        byte[] payerSignature) {

    public static final int TYPE = 'P';
    public static final int VERSION = 1;

    /** What the payer's phone does after the user confirms. */
    public static PaymentToken sign(PaymentRequest request, PayerCertificate certificate, long counter,
                                    long timestamp, PrivateKey payerKey) {
        PaymentToken unsigned = new PaymentToken(certificate.deviceId(), request.receiverDeviceId(),
                request.amountKobo(), counter, timestamp, request.nonce(), certificate, new byte[0]);
        byte[] sig = EcKeys.sign(payerKey, unsigned.headerBytes());
        return unsigned.withSignature(sig);
    }

    public PaymentToken withSignature(byte[] signature) {
        return new PaymentToken(payerDeviceId, receiverDeviceId, amountKobo, counter, timestamp, nonce,
                certificate, signature);
    }

    /** The exact bytes covered by the payer's signature. */
    public byte[] headerBytes() {
        return new Bytes.Writer()
                .u8(TYPE).u8(VERSION)
                .i64(payerDeviceId).i64(receiverDeviceId).i64(amountKobo)
                .i64(counter).i64(timestamp).i64(nonce)
                .toBytes();
    }

    public byte[] encode() {
        return new Bytes.Writer()
                .raw(headerBytes())
                .long16(certificate.encode())
                .short8(payerSignature)
                .toBytes();
    }

    public String toBase64Url() {
        return Bytes.toBase64Url(encode());
    }

    public static PaymentToken decode(byte[] data) {
        Bytes.Reader r = new Bytes.Reader(data);
        if (r.u8() != TYPE) throw new ProtocolException("Not a payment token");
        if (r.u8() != VERSION) throw new ProtocolException("Unsupported token version");
        long payer = r.i64();
        long receiver = r.i64();
        long amount = r.i64();
        long counter = r.i64();
        long ts = r.i64();
        long nonce = r.i64();
        PayerCertificate cert = PayerCertificate.decode(r.long16());
        byte[] sig = r.short8();
        r.expectEnd();
        return new PaymentToken(payer, receiver, amount, counter, ts, nonce, cert, sig);
    }

    public static PaymentToken fromBase64Url(String text) {
        return decode(Bytes.fromBase64Url(text));
    }

    /**
     * Unique ID for this payment: SHA-256 of the signed header, hex.
     * Two submissions of the same token (e.g. payer and receiver both sync it)
     * share the same ID, which is how settlement stays idempotent.
     */
    public String paymentId() {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(headerBytes()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /** Check 2 of offline verification: did the certified payer key sign exactly these fields? */
    public boolean isSignedByCertifiedPayer() {
        try {
            PublicKey payerKey = certificate.payerPublicKey();
            return EcKeys.verify(payerKey, headerBytes(), payerSignature);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
