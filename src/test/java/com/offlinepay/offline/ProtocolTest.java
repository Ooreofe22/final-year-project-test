package com.offlinepay.offline;

import com.offlinepay.offline.crypto.EcKeys;
import com.offlinepay.offline.protocol.*;
import com.offlinepay.offline.protocol.OfflineVerifier.Result;
import com.offlinepay.support.PhoneSimulator;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the offline protocol exactly as two phones would run it with no internet:
 * no database, no server - just keys, certificates, QR payloads and the verifier.
 */
class ProtocolTest {

    private final KeyPair bank = EcKeys.generateKeyPair();
    private final long now = System.currentTimeMillis() / 1000;

    private PhoneSimulator payerWithCertificate(long deviceId, long limitKobo, long expiresAt) {
        PhoneSimulator payer = new PhoneSimulator("Ada");
        payer.setCertificate(PayerCertificate.issue(42, deviceId, payer.publicKeyRaw(), limitKobo,
                now, expiresAt, "Ada", bank.getPrivate()));
        return payer;
    }

    private PhoneSimulator receiver(long deviceId) {
        PhoneSimulator r = new PhoneSimulator("Bayo");
        r.setDeviceId(deviceId);
        return r;
    }

    @Test
    void validPaymentVerifiesOfflineAfterQrRoundTrip() {
        PhoneSimulator ada = payerWithCertificate(1001, 1_000_000, now + 86400);
        PhoneSimulator bayo = receiver(2002);

        // scan 1: Bayo shows a request QR, Ada scans it
        String requestQr = bayo.requestPayment(300_000).toBase64Url();
        PaymentRequest scanned = PaymentRequest.fromBase64Url(requestQr);

        // scan 2: Ada signs, Bayo scans the payment QR
        String paymentQr = ada.pay(scanned).toBase64Url();
        PaymentToken received = PaymentToken.fromBase64Url(paymentQr);

        assertEquals(Result.VALID, OfflineVerifier.verify(received, scanned, bank.getPublic(), now));
        assertEquals(300_000, received.amountKobo());
        assertEquals("Ada", received.certificate().displayName());
    }

    @Test
    void tamperedAmountIsRejected() {
        PhoneSimulator ada = payerWithCertificate(1001, 1_000_000, now + 86400);
        PaymentRequest req = receiver(2002).requestPayment(300_000);
        PaymentToken token = ada.pay(req);

        // attacker edits ₦3,000 to ₦9,000 but cannot re-sign without Ada's key
        PaymentToken edited = new PaymentToken(token.payerDeviceId(), token.receiverDeviceId(), 900_000,
                token.counter(), token.timestamp(), token.nonce(), token.certificate(), token.payerSignature());
        PaymentRequest editedReq = new PaymentRequest(req.receiverDeviceId(), 900_000, req.nonce(), req.receiverName());

        assertEquals(Result.BAD_PAYER_SIGNATURE, OfflineVerifier.verify(edited, editedReq, bank.getPublic(), now));
    }

    @Test
    void forgedCertificateIsRejected() {
        KeyPair fakeBank = EcKeys.generateKeyPair();
        PhoneSimulator mallory = new PhoneSimulator("Mallory");
        mallory.setCertificate(PayerCertificate.issue(1, 666, mallory.publicKeyRaw(), 100_000_000,
                now, now + 86400, "Mallory", fakeBank.getPrivate()));
        PaymentRequest req = receiver(2002).requestPayment(5_000_000);

        assertEquals(Result.CERTIFICATE_NOT_FROM_BANK,
                OfflineVerifier.verify(mallory.pay(req), req, bank.getPublic(), now));
    }

    @Test
    void raisingTheCertificateLimitBreaksTheBankSignature() {
        PhoneSimulator ada = payerWithCertificate(1001, 100_000, now + 86400);
        PayerCertificate real = ada.certificate();
        PayerCertificate inflated = new PayerCertificate(real.serial(), real.deviceId(), real.publicKey(),
                99_000_000, real.issuedAt(), real.expiresAt(), real.displayName(), real.bankSignature());
        assertFalse(inflated.isSignedBy(bank.getPublic()));
    }

    @Test
    void replayedPaymentDoesNotMatchANewRequest() {
        PhoneSimulator ada = payerWithCertificate(1001, 1_000_000, now + 86400);
        PhoneSimulator bayo = receiver(2002);
        PaymentRequest first = bayo.requestPayment(200_000);
        PaymentToken token = ada.pay(first);
        assertEquals(Result.VALID, OfflineVerifier.verify(token, first, bank.getPublic(), now));

        // Bayo creates a fresh request; showing him the old QR again fails on the nonce
        PaymentRequest second = bayo.requestPayment(200_000);
        assertEquals(Result.WRONG_NONCE, OfflineVerifier.verify(token, second, bank.getPublic(), now));
    }

    @Test
    void interceptedPaymentCannotBeRedeemedByAnotherReceiver() {
        PhoneSimulator ada = payerWithCertificate(1001, 1_000_000, now + 86400);
        PaymentToken forBayo = ada.pay(receiver(2002).requestPayment(200_000));

        PaymentRequest thiefRequest = new PaymentRequest(3003, 200_000, forBayo.nonce(), "Thief");
        assertEquals(Result.WRONG_RECEIVER, OfflineVerifier.verify(forBayo, thiefRequest, bank.getPublic(), now));
    }

    @Test
    void expiredCertificateIsRejected() {
        PhoneSimulator ada = payerWithCertificate(1001, 1_000_000, now - 60);
        PaymentRequest req = receiver(2002).requestPayment(100_000);
        assertEquals(Result.CERTIFICATE_EXPIRED, OfflineVerifier.verify(ada.pay(req), req, bank.getPublic(), now));
    }

    @Test
    void paymentAboveCertificateLimitIsRejected() {
        PhoneSimulator ada = payerWithCertificate(1001, 500_000, now + 86400);
        PaymentRequest req = receiver(2002).requestPayment(600_000);
        assertEquals(Result.OVER_CERTIFICATE_LIMIT, OfflineVerifier.verify(ada.pay(req), req, bank.getPublic(), now));
    }

    @Test
    void usingSomeoneElsesCertificateFails() {
        PhoneSimulator ada = payerWithCertificate(1001, 1_000_000, now + 86400);
        PhoneSimulator mallory = new PhoneSimulator("Mallory");
        mallory.setCertificate(ada.certificate()); // copied Ada's certificate, but has his own key
        PaymentRequest req = receiver(2002).requestPayment(100_000);
        assertEquals(Result.BAD_PAYER_SIGNATURE, OfflineVerifier.verify(mallory.pay(req), req, bank.getPublic(), now));
    }

    @Test
    void sameTokenAlwaysHasSamePaymentIdAndCountersDiffer() {
        PhoneSimulator ada = payerWithCertificate(1001, 1_000_000, now + 86400);
        PhoneSimulator bayo = receiver(2002);
        PaymentToken a = ada.pay(bayo.requestPayment(100_000));
        PaymentToken b = ada.pay(bayo.requestPayment(100_000));

        assertEquals(a.paymentId(), PaymentToken.fromBase64Url(a.toBase64Url()).paymentId());
        assertNotEquals(a.paymentId(), b.paymentId());
        assertEquals(0, a.counter());
        assertEquals(1, b.counter());
    }

    @Test
    void garbageAndTruncatedQrCodesAreRejectedCleanly() {
        assertThrows(ProtocolException.class, () -> PaymentToken.fromBase64Url("not base64 !!"));
        assertThrows(ProtocolException.class, () -> PaymentToken.fromBase64Url("UAE"));

        PhoneSimulator ada = payerWithCertificate(1001, 1_000_000, now + 86400);
        String full = ada.pay(receiver(2002).requestPayment(100_000)).toBase64Url();
        assertThrows(ProtocolException.class, () -> PaymentToken.fromBase64Url(full.substring(0, full.length() - 20)));
    }

    @Test
    void androidStyleX509PublicKeyIsAccepted() {
        PhoneSimulator ada = new PhoneSimulator("Ada");
        byte[] fromX509 = EcKeys.normalizeToRaw(ada.publicKeyX509());
        assertArrayEquals(ada.publicKeyRaw(), fromX509);
        assertArrayEquals(ada.publicKeyRaw(), EcKeys.normalizeToRaw(ada.publicKeyRaw()));
        assertThrows(IllegalArgumentException.class, () -> EcKeys.normalizeToRaw(new byte[]{1, 2, 3}));
    }

    @Test
    void paymentQrFitsComfortablyInOneQrCode() {
        PhoneSimulator ada = payerWithCertificate(1001, 1_000_000, now + 86400);
        String qr = ada.pay(receiver(2002).requestPayment(100_000)).toBase64Url();
        int bytes = Base64.getUrlDecoder().decode(qr).length;
        // A version-40 QR holds 2,331 bytes at error-correction level M; we stay far below it
        assertTrue(bytes < 400, "token is " + bytes + " bytes");
        assertTrue(qr.length() < 600, "QR text is " + qr.length() + " characters");
    }
}
