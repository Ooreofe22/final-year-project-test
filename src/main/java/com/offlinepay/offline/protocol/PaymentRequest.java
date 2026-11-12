package com.offlinepay.offline.protocol;

import java.security.SecureRandom;

/**
 * Scan 1 - shown as a QR code on the RECEIVER's phone.
 * "Device {receiverDeviceId} ({receiverName}) asks for {amountKobo}; reference {nonce}."
 *
 * Not signed: it only tells the payer what to sign. The nonce and receiver ID end up
 * inside the payer's signed token, which is what locks the payment to this request.
 *
 * Byte layout:
 *   u8 type = 'R' (0x52), u8 version = 1,
 *   i64 receiverDeviceId, i64 amountKobo, i64 nonce, u8+n receiverName (UTF-8)
 */
public record PaymentRequest(long receiverDeviceId, long amountKobo, long nonce, String receiverName) {

    public static final int TYPE = 'R';
    public static final int VERSION = 1;
    private static final SecureRandom RANDOM = new SecureRandom();

    public static PaymentRequest create(long receiverDeviceId, long amountKobo, String receiverName) {
        if (amountKobo <= 0) throw new IllegalArgumentException("Amount must be positive");
        return new PaymentRequest(receiverDeviceId, amountKobo, RANDOM.nextLong(), receiverName == null ? "" : receiverName);
    }

    public byte[] encode() {
        return new Bytes.Writer()
                .u8(TYPE).u8(VERSION)
                .i64(receiverDeviceId).i64(amountKobo).i64(nonce)
                .text8(receiverName)
                .toBytes();
    }

    public String toBase64Url() {
        return Bytes.toBase64Url(encode());
    }

    public static PaymentRequest decode(byte[] data) {
        Bytes.Reader r = new Bytes.Reader(data);
        if (r.u8() != TYPE) throw new ProtocolException("Not a payment request");
        if (r.u8() != VERSION) throw new ProtocolException("Unsupported request version");
        PaymentRequest req = new PaymentRequest(r.i64(), r.i64(), r.i64(), r.text8());
        r.expectEnd();
        if (req.amountKobo() <= 0) throw new ProtocolException("Amount must be positive");
        return req;
    }

    public static PaymentRequest fromBase64Url(String text) {
        return decode(Bytes.fromBase64Url(text));
    }
}
