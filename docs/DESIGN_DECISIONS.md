# Design decisions

These decisions were agreed while planning the project. The backend and the report (Chapter 3) both follow them.

## 1. Lost or stolen phones: revocation and liability

While offline, a seller's phone can only check what is inside the payment itself. A freeze at the bank stays invisible to it until the seller syncs. So a stolen phone can keep paying offline sellers until its certificate expires, which is up to 7 days.

- **Normal app on a stolen phone:** the app won't sign beyond the offline balance, so the thief can spend at most what was reserved. That money was already set aside at top-up. The only question is who carries it: the owner or the bank.
- **Tampered app:** the chip signs whatever it is asked to, so many sellers can each be paid up to the limit. Revocation matters most here.

**Decision.** Combine three things:

1. **A revocation list sent with every sync.** It lists the serials frozen in the last 7 days. The seller's app rejects payments from a revoked certificate with `CERTIFICATE_REVOKED`.
2. **A key that dies when new biometrics are enrolled.** On Android this is `setInvalidatedByBiometricEnrollment(true)`; on iOS, `biometryCurrentSet`.
3. **A written liability rule**, modelled on the Reserve Bank of India's offline payments framework.

| When the payment was signed | Seller | Owner of the stolen phone | Bank |
|---|---|---|---|
| Before the owner reported it | Paid | Bears the loss, like lost cash | Nothing to absorb |
| After the report, and the seller hadn't synced since | Paid | Refunded | Absorbs it, capped at the offline balance |
| After the report, and the seller's phone already had the freeze | Not paid: the app should have rejected it | Refunded | Nothing |

**Future work:** shorter certificates, a daily cap per certificate, and passing the revocation list from phone to phone.

## 2. Interrupted payments: "save first", on hold and release

A QR code only travels one way, so the payer's phone can never know whether the seller scanned it. A signed payment therefore can't be cancelled offline.

| # | Breaks at | What should happen |
|---|---|---|
| 1 | Payer's phone dies before Face ID | Nothing was signed. Start again |
| 2 | Payer signed; the seller never scanned | The payer's money goes **on hold**. Reopening the app shows the same code. If it's never claimed, it is released |
| 3 | The seller verified, then the phone died before saving | The payer's sync settles it, so the seller is still paid |
| 4 | The seller's check failed | Same as 2 |
| 5 | Both saved, then one phone is lost before syncing | The other side's sync settles it |
| 6 | Both phones lost before either syncs | Lost, like dropped cash. This is a known limitation, reported in Chapter 5 |

**The save-first rule.** The payer's app writes the signed payment, the new counter and the lower balance to storage in one database transaction *before* showing the QR. The seller's app writes the accepted payment *before* showing the tick.

**The release rule.**
1. A payment that was signed but not confirmed shows as "on hold", not as spent.
2. The bank pays the seller whenever the seller submits it, up to the certificate's expiry.
3. After `cert.expiresAt` plus a 24-hour grace period, the seller can no longer claim it. At the payer's next sync, the money returns to the payer's main balance.

Backend pieces: the `ON_HOLD` and `RELEASED` statuses, a `release_unclaimed` job, and the server-side settlement deadline (backend change 1).

Payment states: **Signed → On hold → Settled, or Released.**

**Disputes.** A signed payment is final. A refund is a new payment back. If goods are never handed over, the buyer opens a dispute online, and the signed receipt proves the amount, the time and the seller's device.

## 3. Device support: limits by hardware level

Most Nigerian phones are Tecno, Infinix or itel, and they mostly have a TEE but no StrongBox. The levels:

| Level | Offline limit |
|---|---|
| Secure chip (StrongBox, Secure Enclave) | ₦20,000 |
| TEE | ₦10,000 (configurable) |
| Software only, rooted, or failed the integrity check | No offline certificate; online only |

The level is proven at sign-up with Android key attestation or iOS App Attest. Key use requires strong biometrics **or** the device PIN (`BIOMETRIC_STRONG | DEVICE_CREDENTIAL`), because budget-phone face unlock is usually not rated Class 3.

## 4. Trusted clock (app side, but the server enforces the hard limit)

The app keeps a clock that changing the date in Settings can't move:
- It anchors to the bank's `issuedAt` whenever a certificate arrives.
- It counts forward with the time since boot: `SystemClock.elapsedRealtime()` on Android, `mach_continuous_time()` on iOS.
- It saves the last known time, uses the boot count to survive restarts, and never goes backwards.

The server's settlement deadline (backend change 1) is the hard limit against a tampered app.

## 5. Scope

- Face-to-face payments, QR codes only. No NFC or Bluetooth.
- A simulated bank, with no real money and no connection to NIBSS.
- No privacy from the bank: the bank must see each payment to settle it.
