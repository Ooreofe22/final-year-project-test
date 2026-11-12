# Offline Payment Protocol

Every QR code carries one binary message, encoded as **base64url without padding**. All integers are **big-endian**. Amounts are in **kobo** (₦1 = 100 kobo). Times are **Unix epoch seconds**.

Cryptography: **ECDSA on P-256** (secp256r1) with **SHA-256**, signatures **DER-encoded** (`SHA256withECDSA` in Java/Android). Public keys are the **65-byte uncompressed point** `0x04 || X || Y`.

Reference implementation: `src/main/java/com/offlinepay/offline/protocol/`.

## 1. Payer certificate (issued by the bank, stored on the payer's phone)

| Field | Size | Notes |
|---|---|---|
| type | 1 | `0x43` ('C') |
| version | 1 | `1` |
| serial | 8 | Unique per certificate |
| deviceId | 8 | Payer's device |
| publicKey | 65 | Payer's hardware key |
| limitKobo | 8 | Money the bank has reserved for this device |
| issuedAt | 8 | |
| expiresAt | 8 | |
| displayName | 1 + n | Length byte, then UTF-8 (max 60 bytes) |
| **bankSignature** | 1 + n | Length byte, then DER signature over **all fields above** |

Typical size: **194 bytes**.

## 2. Payment request (scan 1: receiver → payer)

| Field | Size | Notes |
|---|---|---|
| type | 1 | `0x52` ('R') |
| version | 1 | `1` |
| receiverDeviceId | 8 | |
| amountKobo | 8 | Must be > 0 |
| nonce | 8 | Fresh random value for every request |
| receiverName | 1 + n | Length byte, then UTF-8 |

Not signed. It only tells the payer what to sign. Typical size: **39 bytes (52 QR characters)**.

## 3. Payment token (scan 2: payer → receiver). This is the money

| Field | Size | Notes |
|---|---|---|
| type | 1 | `0x50` ('P') |
| version | 1 | `1` |
| payerDeviceId | 8 | |
| receiverDeviceId | 8 | Copied from the request |
| amountKobo | 8 | Copied from the request |
| counter | 8 | 0, 1, 2… increases by one for every payment from this device |
| timestamp | 8 | Payer's clock |
| nonce | 8 | Copied from the request |
| certificate | 2 + n | 2-byte length, then the payer certificate (section 1) |
| **payerSignature** | 1 + n | Length byte, then DER signature over the **first 50 bytes** (type … nonce) |

Typical size: **317 bytes (423 QR characters)**. A QR code at error-correction level M holds up to 2,331 bytes, so there is plenty of room.

**Payment ID** = lowercase hex SHA-256 of the first 50 bytes. The same token always has the same ID; this is how settlement stays idempotent.

## 4. Offline verification (receiver's phone, no internet)

In this order (`OfflineVerifier.java`):

1. Bank signature on the certificate is valid (using the bank public key bundled in the app)
2. Certificate is not expired (receiver's clock)
3. `certificate.deviceId == token.payerDeviceId`
4. Payer signature on the token is valid (using the key inside the certificate)
5. `token.receiverDeviceId` is **my** device ID
6. `token.nonce` equals the nonce of the request **I** just showed
7. `token.amountKobo` equals the amount I requested
8. `0 < amountKobo <= certificate.limitKobo`

All pass → show "Payment verified", store the token as *pending sync*, and never accept that nonce again.

## 5. Rules for the payer's phone

- The private key is generated **inside Android Keystore** and is never exported.
- Require **fingerprint or PIN** before every signature.
- **Increment and save the counter before showing the QR.** Never reuse a counter, even if the payment is cancelled; the server treats a reused counter as a double-spend.
- Track the local offline balance: reserved amount minus unsynced payments sent. Refuse to sign when it would go below zero.
- Keep every signed token until the server confirms it was settled.
