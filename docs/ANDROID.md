# Building the Android App Against This Backend

The phone app is the next part of the project. This guide maps each screen and step to the backend API and the protocol classes. The code snippets are a starting point in Kotlin; they have not been compiled.

## Recommended stack

| Need | Library |
|---|---|
| Language / UI | Kotlin, Jetpack Compose |
| Hardware key + signing | Android Keystore (`AndroidKeyStore`), `BiometricPrompt` |
| QR generation | ZXing core (`com.google.zxing:core`) |
| QR scanning | ML Kit Barcode Scanning + CameraX |
| HTTP | Retrofit + Moshi (or Ktor) |
| Local storage | Room (pending tokens, counter, certificate) |
| Background sync | WorkManager with a "network connected" constraint |

## Step 1: Copy the protocol code

Copy these packages from this repo into the app **unchanged**. They only use the Java standard library:

```
offline/crypto/EcKeys.java
offline/protocol/*.java
```

Android can compile Java alongside Kotlin, so the app and the server use byte-for-byte the same formats.

## Step 2: Generate the hardware key (first launch)

```kotlin
val spec = KeyGenParameterSpec.Builder("payer_key", KeyProperties.PURPOSE_SIGN)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setUserAuthenticationRequired(true)                       // fingerprint/PIN before each use
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
    .setIsStrongBoxBacked(hasStrongBox)                        // use StrongBox when the phone has it
    .build()
val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
gen.initialize(spec)
val publicKey = gen.generateKeyPair().public

// Register with the bank: POST /offline/devices { publicKey: base64(publicKey.encoded) }
val body = mapOf("publicKey" to Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP), "label" to Build.MODEL)
```

The server accepts Android's X.509 encoding directly.

## Step 3: Load the wallet (online)

`POST /offline/wallet/load {"amount": 10000}` returns a `certificate` string. Decode and store it:

```kotlin
val cert = PayerCertificate.fromBase64Url(response.certificate)
check(cert.isSignedBy(EcKeys.fromRaw(BANK_PUBLIC_KEY_RAW)))   // never trust the network blindly
```

Get `BANK_PUBLIC_KEY_RAW` once from `GET /offline/bank-public-key` and **ship it inside the app**, so verification never needs the internet.

## Step 4: Receive screen (offline)

```kotlin
val request = PaymentRequest.create(myDeviceId, amountKobo, myName)
pendingRequest = request                       // remember the nonce
showQr(request.toBase64Url())                  // ZXing: QRCodeWriter().encode(text, QR_CODE, 600, 600)
```

## Step 5: Pay screen (offline)

```kotlin
val request = PaymentRequest.fromBase64Url(scannedText)
// Show "Pay ₦X to <request.receiverName()>?" and get a fingerprint:
val signature = Signature.getInstance("SHA256withECDSA").apply {
    initSign(keyStore.getKey("payer_key", null) as PrivateKey)
}
BiometricPrompt(activity, executor, callback).authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))

// in onAuthenticationSucceeded:
val counter = counterStore.incrementAndSave()          // save BEFORE showing the QR
val unsigned = PaymentToken(cert.deviceId(), request.receiverDeviceId(), request.amountKobo(),
        counter, System.currentTimeMillis() / 1000, request.nonce(), cert, ByteArray(0))
val sig = result.cryptoObject!!.signature!!.run { update(unsigned.headerBytes()); sign() }
val token = unsigned.withSignature(sig)
pendingTokens.insert(token.toBase64Url())              // keep until settled
showQr(token.toBase64Url())
```

Before signing, check the local offline balance (reserved minus unsynced payments sent) covers the amount.

## Step 6: Verify the payment (receiver, offline)

```kotlin
val token = PaymentToken.fromBase64Url(scannedText)
val result = OfflineVerifier.verify(token, pendingRequest, EcKeys.fromRaw(BANK_PUBLIC_KEY_RAW),
        System.currentTimeMillis() / 1000)
if (result == OfflineVerifier.Result.VALID) {
    pendingTokens.insert(scannedText)
    pendingRequest = null                     // this nonce can never be accepted again
    showSuccess("₦${token.amountKobo() / 100.0} from ${token.certificate().displayName()}")
} else showError(result.name)
```

## Step 7: Sync (when online)

A WorkManager job with `NetworkType.CONNECTED` posts every pending token, sent and received:

```
POST /offline/sync  { "tokens": ["...", "..."] }
```

Remove tokens whose result is `SETTLED` or `ALREADY_SETTLED`. Show `REJECTED` ones to the user with their reason, then remove them.

## Demo build for the evaluation

Add a hidden debug menu (debug builds only) with buttons that deliberately:

- **Replay**: show the last payment QR again
- **Tamper**: change the amount in a token without re-signing
- **Double-spend**: sign with the previous counter instead of the next one

The receiver's phone should reject the first two on the spot; the bank dashboard should flag the third the moment either receiver syncs. `PhoneSimulator` in `src/test` shows exactly how each attack is built.
