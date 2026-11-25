# Offline QR Payments: Mock Bank Backend

Final year project: **Design and Implementation of a Secure Offline Peer-to-Peer Payment System Using Digitally Signed QR Code Tokens.**

Two phones complete a payment face to face with **no internet** by scanning QR codes. The payer's phone signs the payment with a key locked inside its secure hardware; the receiver's phone verifies it offline using a certificate the bank signed earlier. When either phone reconnects, this server settles the payment, and catches anyone who tried to cheat.

This repository is the **bank side** (Java 21, Spring Boot 3). The Android app talks to it; see [`docs/ANDROID.md`](docs/ANDROID.md).

---

## Features

### Accounts and login
- Passwordless sign-up and login with one-time codes sent by email (codes are printed to the console in dev mode)
- JWT access tokens (15 min) and refresh tokens (30 days), one active session per user
- Every new user starts with **₦50,000 test naira** so the demo has money to move
- Display name on every account, shown to the other person during a payment ("Payment from Ada")

### Offline wallet
- **Device registration**: each phone registers its public key; the private key never leaves the phone
- **Load**: move money from the main balance into the offline wallet (capped at **₦20,000** by default)
- **Unload**: move unspent offline money back to the main balance
- **Bank certificate**: issued on every load, signed with the bank's key, valid for **7 days**, and its limit equals the money actually reserved
- **Renew certificate** without reloading
- One active phone per user; a new phone can only be registered once the old phone's wallet is empty

### Offline payments (the protocol)
- **Two-scan QR handshake**: receiver shows a request QR, payer scans it, signs, and shows a payment QR
- **ECDSA P-256 signatures** (SHA256withECDSA), the same algorithm Android Keystore runs in secure hardware
- Compact binary format: payment QR is **317 bytes / 423 characters**, far below one QR code's capacity
- `OfflineVerifier`: the exact checks the receiver's phone runs with no internet, ready to port to Kotlin

### Settlement and fraud detection
- `POST /offline/sync`: phones upload payments they made or received; each one settles independently
- **Idempotent**: payer and receiver can both upload the same payment and it settles exactly once
- **13 ordered checks** on every payment (see below)
- **Double-spend detection**: two different payments with the same counter
- **Overspend detection**: paying out more than the bank reserved
- **Bank guarantee**: an honest receiver is always paid; the bank recovers the shortfall from the cheater (offline reserve first, then main balance) and **freezes their device**
- Row-level locking in a fixed order, so simultaneous syncs never double-credit or deadlock

### Bank dashboard and audit trail
- **Live dashboard** at `/dashboard.html` (refreshes every 2 s): accounts, settled payments, devices, blocked attacks and fraud alerts. Made for projecting during the defence
- Admin API: statistics, accounts, devices, payments, flagged payments, security events
- Admin can suspend/reactivate accounts and unfreeze a device after review
- **Security event log**: every rejected or suspicious payment is recorded by type, which feeds the evaluation chapter's attack statistics

### Tests
- `ProtocolTest`: 13 tests of the offline protocol with no server: valid payment, tampering, forged certificate, raised limit, replay, interception, expiry, over-limit, stolen certificate, counters, garbage input, Android key format, QR size. **All 13 pass.**
- `SettlementIntegrationTest`: 11 end-to-end tests against a real database: loading, settle-once, tampering, forgery, garbage input, stranger submission, **double-spend**, **overspend**, wallet limit, unload, phone replacement
  These were written alongside the code but have **not been run yet**: run `mvn test` and fix anything that fails before relying on them.
- `PhoneSimulator`: a test helper that behaves like a phone, including an attack mode that reuses counters

---

## Threat model: what each attack hits

| Attack | Blocked offline by the receiver's phone | Caught at settlement |
|---|---|---|
| Edit the amount or receiver after signing | ✅ signature fails | ✅ `TAMPERED_TOKEN` |
| Forge a certificate / invent a wallet | ✅ bank signature fails | ✅ `FORGED_CERTIFICATE` |
| Raise the limit inside a real certificate | ✅ bank signature fails | ✅ `FORGED_CERTIFICATE` |
| Show the same payment QR again (replay) | ✅ nonce doesn't match the new request | ✅ settles once only |
| Photograph someone else's payment QR | ✅ receiver ID doesn't match | ✅ `NOT_A_PARTY` |
| Use someone else's certificate with your own key | ✅ signature fails | ✅ `TAMPERED_TOKEN` |
| Pay with an expired certificate | ✅ `CERTIFICATE_EXPIRED` | ✅ `CERTIFICATE_EXPIRED` |
| Pay more than the certificate allows | ✅ `OVER_CERTIFICATE_LIMIT` | ✅ `OVER_CERTIFICATE_LIMIT` |
| **Double-spend** (same money to two people offline) | ❌ impossible to detect offline | ✅ `DOUBLE_SPEND`, receiver paid, payer frozen |
| **Overspend** (spend more than reserved) | ❌ impossible to detect offline | ✅ `OVERSPEND`, receiver paid, payer frozen |
| Stolen phone | PIN/fingerprint before every payment (app side) | Admin can suspend the account (blocks new loads) |

Double-spending can never be prevented offline, only **detected and punished** after sync. This is the honest limit of every offline payment system. The design keeps the risk **bounded**: each payment is capped by the certificate limit (≤ ₦20,000), certificates expire after 7 days, and a cheater is frozen as soon as either victim syncs.

### The 13 settlement checks, in order

1. Token parses → else `MALFORMED_TOKEN`
2. Certificate signed by the bank → else `FORGED_CERTIFICATE`
3. Certificate belongs to the claimed payer device → else `CERTIFICATE_DEVICE_MISMATCH`
4. Payer's signature matches the payment details → else `TAMPERED_TOKEN`
5. Payer and receiver devices exist → else `UNKNOWN_DEVICE`
6. Certificate key matches the registered device key → else `KEY_MISMATCH`
7. Certificate was valid when the payment was signed → else `CERTIFICATE_EXPIRED`
8. Amount within the certificate's limit → else `OVER_CERTIFICATE_LIMIT`
9. Submitter is the payer or the receiver → else `NOT_A_PARTY`
10. Already settled? → `ALREADY_SETTLED` (harmless)
11. Counter already used by a different payment? → `DOUBLE_SPEND`
12. Reserve too small? → `OVERSPEND`
13. Otherwise → `SETTLED`

---

## Running it

**Requirements:** Java 21 and Maven 3.9+ (or open the folder in IntelliJ as a Maven project).

```bash
mvn spring-boot:run
```

With no configuration this runs the **dev profile**: an H2 database stored in `./data`, a dev-only JWT secret, and one-time codes printed to the console. The server listens on **http://localhost:8081**.

Run the tests:

```bash
mvn test
```

Open the dashboard at **http://localhost:8081/dashboard.html** and enter the admin key (`changeme-admin-key` unless you set `ADMIN_API_KEY`).

**Testing from real phones:** the phones must reach your laptop. Put both on the same Wi-Fi (or your laptop's hotspot), find your laptop's local IP (`ipconfig` on Windows, `ip a` on Linux), and point the app at `http://<that-ip>:8081`. Turn airplane mode on only *after* loading the wallet.

### Configuration

Copy `.env.example` and set values as environment variables (IntelliJ: Run → Edit Configurations → Environment variables).

| Variable | Default | Meaning |
|---|---|---|
| `SPRING_PROFILE` | `dev` | `dev` = H2 + console OTPs, `prod` = PostgreSQL + real emails |
| `JWT_SECRET` | dev-only value | **Required in prod**, at least 32 characters |
| `ADMIN_API_KEY` | `changeme-admin-key` | Dashboard / admin API key. Change it |
| `WALLET_SIGNUP_BONUS` | `50000` | Test naira for each new user |
| `OFFLINE_WALLET_LIMIT` | `20000` | Max naira in an offline wallet |
| `OFFLINE_CERT_VALIDITY_DAYS` | `7` | Certificate lifetime |
| `OFFLINE_BANK_PRIVATE_KEY` / `OFFLINE_BANK_PUBLIC_KEY` | empty | Optional fixed bank key; otherwise generated once and stored in the database |
| `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` | | PostgreSQL (prod profile) |
| `RESEND_API_KEY`, `RESEND_FROM` | | Email sending (prod profile) |

---

## API

All amounts are in **naira** in JSON; inside QR tokens they are in **kobo**. Endpoints except `/auth/**`, `/admin/**` and `GET /offline/bank-public-key` need `Authorization: Bearer <accessToken>`.

### Auth
| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/auth/signup/request-otp` | `{email, displayName, bvn?}` | Sends a code |
| POST | `/auth/signup/verify-otp` | `{email, displayName, bvn?, otp}` | Creates the account, returns tokens |
| POST | `/auth/login/request-otp` | `{email}` | |
| POST | `/auth/login/verify-otp` | `{email, otp}` | Returns `accessToken`, `refreshToken`, `userId`, `displayName`, `balance` |
| POST | `/auth/refresh` | `{refreshToken}` | New access token |
| POST | `/auth/logout` | `{refreshToken}` | Revokes the session |

### Offline wallet and payments
| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/offline/bank-public-key` | | Bank key (`publicKeyRaw`, `publicKeyX509`), baked into the app |
| POST | `/offline/devices` | `{publicKey, label}` | `deviceId`. `publicKey` is standard base64 of the X.509 or raw 65-byte key |
| GET | `/offline/wallet` | | Main balance, offline reserve, limit, device status, certificate expiry |
| POST | `/offline/wallet/load` | `{amount}` | Same as above **plus a new `certificate`** (store it on the phone) |
| POST | `/offline/wallet/unload` | `{amount}` | Same, with a new certificate if money remains |
| POST | `/offline/wallet/certificate` | | Renewed certificate |
| POST | `/offline/sync` | `{tokens: ["<payment QR text>", ...]}` | Per-token result: `SETTLED`, `ALREADY_SETTLED` or `REJECTED` with a reason and fraud flag |
| GET | `/offline/payments` | | Your settled payments, sent and received |

### Admin (header `X-Admin-Key`)
`GET /admin/stats` · `GET /admin/accounts` · `POST /admin/accounts/{id}/suspend` · `POST /admin/accounts/{id}/reactivate` · `GET /admin/devices` · `POST /admin/devices/{id}/unfreeze` · `GET /admin/payments` · `GET /admin/payments/flagged` · `GET /admin/security-events`

### Quick try with curl

```bash
# 1. sign up (the code appears in the server console)
curl -X POST localhost:8081/auth/signup/request-otp -H 'Content-Type: application/json' \
     -d '{"email":"ada@test.ng","displayName":"Ada"}'
curl -X POST localhost:8081/auth/signup/verify-otp -H 'Content-Type: application/json' \
     -d '{"email":"ada@test.ng","displayName":"Ada","otp":"123456"}'

# 2. register a phone key, then load ₦10,000 (use the accessToken from step 1)
curl -X POST localhost:8081/offline/devices -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"publicKey":"<base64 public key>","label":"Ada Pixel"}'
curl -X POST localhost:8081/offline/wallet/load -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"amount":10000}'
```

---

## Project structure

```
src/main/java/com/offlinepay/
├── auth/            OTP sign-up/login, sessions, email (reused from xpressPay-backend)
├── security/        JWT service and filter (reused)
├── config/          Spring Security setup
├── model/           User, sessions, OTP codes
├── admin/           Bank dashboard API
├── exception/       Consistent JSON error responses
└── offline/
    ├── crypto/      EcKeys: P-256 keys, signing, key formats
    ├── protocol/    PayerCertificate, PaymentRequest, PaymentToken, OfflineVerifier  ← port these to Android
    ├── model/       Device, OfflinePayment, SecurityEvent, BankKey
    ├── repository/  Database access
    ├── service/     BankKeyService, OfflineWalletService, SettlementService
    └── web/         OfflineController
src/main/resources/static/dashboard.html   Live bank dashboard
docs/PROTOCOL.md     Exact byte layouts of every QR message
docs/ANDROID.md      How to build the phone app against this backend
```

The `offline/protocol` and `offline/crypto` packages use **only the Java standard library**, so they can be copied into the Android project as they are.

---

## Known limitations

- **Mock bank only**: no real money moves. A real launch needs a CBN licence or a partnership with a licensed bank or fintech.
- **Bank key in the database**: a real bank would keep it in a hardware security module (HSM).
- **Admin authentication** is a shared header key: fine for a demo, not for production.
- **Unload trusts the phone** to have synced its payments first; if it lied, the next sync catches it as an overspend and recovers the money.
- **Double-spend can only be detected, not prevented**, offline (see the threat model).

Built on the auth and security modules of `xpressPay-backend`; the biller, Paystack and virtual-account code was left out because this project doesn't need it.

## Author

**Ooreofeoluwa Popoola**, B.Tech. Information Technology, Bells University of Technology.
[Portfolio](https://ooreofepopoola.dev) · [LinkedIn](https://www.linkedin.com/in/ooreofeoluwa-popoola-8260ba3b4/) · [GitHub](https://github.com/Ooreofe22)
