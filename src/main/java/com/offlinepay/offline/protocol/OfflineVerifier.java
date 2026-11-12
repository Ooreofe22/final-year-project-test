package com.offlinepay.offline.protocol;

import java.security.PublicKey;

/**
 * The checks the RECEIVER's phone runs with no internet, in this order.
 * The server runs the same checks again at settlement time.
 * The Android app should port this class line by line.
 */
public final class OfflineVerifier {

    public enum Result {
        VALID,
        CERTIFICATE_NOT_FROM_BANK,     // forged or edited certificate
        CERTIFICATE_EXPIRED,
        CERTIFICATE_DEVICE_MISMATCH,   // token claims a different payer than its certificate
        BAD_PAYER_SIGNATURE,           // amount/receiver/etc edited after signing
        WRONG_RECEIVER,                // token was made for someone else (intercepted QR)
        WRONG_NONCE,                   // token does not answer this request (replayed QR)
        WRONG_AMOUNT,
        OVER_CERTIFICATE_LIMIT
    }

    private OfflineVerifier() {}

    public static Result verify(PaymentToken token, PaymentRequest expected, PublicKey bankPublicKey,
                                long nowEpochSeconds) {
        PayerCertificate cert = token.certificate();

        if (!cert.isSignedBy(bankPublicKey)) return Result.CERTIFICATE_NOT_FROM_BANK;
        if (cert.isExpiredAt(nowEpochSeconds)) return Result.CERTIFICATE_EXPIRED;
        if (cert.deviceId() != token.payerDeviceId()) return Result.CERTIFICATE_DEVICE_MISMATCH;
        if (!token.isSignedByCertifiedPayer()) return Result.BAD_PAYER_SIGNATURE;

        if (expected != null) {
            if (token.receiverDeviceId() != expected.receiverDeviceId()) return Result.WRONG_RECEIVER;
            if (token.nonce() != expected.nonce()) return Result.WRONG_NONCE;
            if (token.amountKobo() != expected.amountKobo()) return Result.WRONG_AMOUNT;
        }
        if (token.amountKobo() <= 0 || token.amountKobo() > cert.limitKobo()) return Result.OVER_CERTIFICATE_LIMIT;
        return Result.VALID;
    }
}
