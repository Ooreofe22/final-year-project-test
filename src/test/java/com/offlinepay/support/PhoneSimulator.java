package com.offlinepay.support;

import com.offlinepay.offline.crypto.EcKeys;
import com.offlinepay.offline.protocol.PayerCertificate;
import com.offlinepay.offline.protocol.PaymentRequest;
import com.offlinepay.offline.protocol.PaymentToken;

import java.security.KeyPair;

/**
 * Plays the part of a phone in tests: holds a key pair (in real life, inside Android
 * Keystore), a certificate from the bank, and a payment counter.
 * The Android app does exactly these steps.
 */
public class PhoneSimulator {

    private final KeyPair keys = EcKeys.generateKeyPair();
    private PayerCertificate certificate;
    private long deviceId;
    private long counter = 0;
    private final String name;

    public PhoneSimulator(String name) {
        this.name = name;
    }

    public byte[] publicKeyRaw() {
        return EcKeys.toRaw(keys.getPublic());
    }

    public byte[] publicKeyX509() {
        return keys.getPublic().getEncoded();
    }

    public KeyPair keys() {
        return keys;
    }

    public String name() {
        return name;
    }

    public void setDeviceId(long deviceId) {
        this.deviceId = deviceId;
    }

    public long deviceId() {
        return deviceId;
    }

    public void setCertificate(PayerCertificate certificate) {
        this.certificate = certificate;
        this.deviceId = certificate.deviceId();
    }

    public PayerCertificate certificate() {
        return certificate;
    }

    /** Receiver side, scan 1: show a request QR. */
    public PaymentRequest requestPayment(long amountKobo) {
        return PaymentRequest.create(deviceId, amountKobo, name);
    }

    /** Payer side, scan 2: sign and show the payment QR. Counter goes up every time. */
    public PaymentToken pay(PaymentRequest request) {
        return PaymentToken.sign(request, certificate, counter++, System.currentTimeMillis() / 1000, keys.getPrivate());
    }

    /** ATTACK helper: sign with a counter of the attacker's choosing (e.g. reuse one to double-spend). */
    public PaymentToken payWithCounter(PaymentRequest request, long forcedCounter) {
        return PaymentToken.sign(request, certificate, forcedCounter, System.currentTimeMillis() / 1000, keys.getPrivate());
    }
}
