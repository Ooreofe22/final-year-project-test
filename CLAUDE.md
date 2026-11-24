# CLAUDE.md: Owo offline payments backend

This file gives Claude Code the full context of the project, carried over from the planning conversation on claude.ai. Read it fully before changing anything.

## What this project is

- **Owner:** Ooreofeoluwa Popoola Kayode ("Marino"), final-year B.Tech. Information Technology student at Bells University of Technology, Ota, Nigeria.
- **Final-year project title:** *Design and Implementation of a Secure Offline Peer-to-Peer Payment System Using Digitally Signed QR Code Tokens.*
- **App name in the report:** Owo. Package and some code still say `offlinepay`. Don't rename packages.
- **This repo:** the Spring Boot backend, acting as a **simulated bank**. It registers devices, reserves offline funds, issues bank-signed certificates and settles offline payments when a phone syncs. No real money moves.
- **The app:** a Flutter app, built later in a separate repo. It is Android first, with an iPhone build via the free Xcode Personal Team route. Signing runs in native Kotlin and Swift inside the phone's secure hardware (Android Keystore/StrongBox, Apple Secure Enclave).

## How a payment works

1. **Online, before paying.** The payer reserves money (`POST /offline/wallet/load`). The bank issues a **payer certificate** (`POST /offline/wallet/certificate`) binding the device's public key to a limit and a 7-day expiry, signed by the bank.
2. **Offline, scan 1.** The receiver shows a **payment request** QR: receiver device ID, amount, fresh nonce.
3. **Offline, scan 2.** The payer's phone signs a **payment token** in secure hardware and shows it as a QR. The token holds payer and receiver IDs, amount, counter, timestamp and nonce, plus the certificate.
4. **Offline check.** The receiver's phone verifies the certificate and the signature offline (`OfflineVerifier`).
5. **Online, later.** Either phone uploads the token to `POST /offline/sync`. `SettlementService` runs its checks, credits the receiver exactly once, and detects double-spend and overspend.

The byte formats, field sizes and verification order are specified in `docs/PROTOCOL.md`. **That spec is the contract with the Flutter app.**

## Cryptography and units

- ECDSA P-256 with SHA-256 (`SHA256withECDSA`), DER signatures.
- Public keys are 65-byte uncompressed points.
- Payment ID = lowercase hex SHA-256 of the token's first 50 bytes, which excludes the signature. This makes signature malleability harmless and makes sync idempotent.
- Amounts are in **kobo** (₦1 = 100 kobo), as `long`. Times are Unix epoch seconds.
- QR codes carry base64url without padding.

## Hard rules: do not break these

1. **Never change the byte format** of the certificate, request or token without updating `docs/PROTOCOL.md` and `ProtocolTest`, and telling the owner. The Flutter app must produce identical bytes.
2. **Keep the settlement check order** in `SettlementService`:
   - parse
   - crypto (2–4)
   - devices (5)
   - certificate consistency (6–8)
   - party check (9)
   - idempotency under locks (10)
   - fraud (11–12)
   - move money

   New checks are inserted *around* this order, never by reshuffling it.
3. **Lock order** is users (sorted by id), then the payer's device. `OfflineWalletService` uses the same order, which is what prevents deadlocks.
4. **The receiver is always paid** for a payment that passed the offline checks. Fraud is recovered from the payer, and the payer's device is frozen. This is the bank guarantee the report argues for.
5. **Every rejection is written to the security-event log** (`SecurityEvent`) with its reason. The log is the evidence for Chapter 4.
6. Money moves from the reserve first; any shortfall comes from the payer's main balance.
7. Stack: Java 21, Spring Boot 3.3.4, PostgreSQL (H2 in tests), jjwt 0.12.6. Keep the versions pinned, because Chapter 3 must list exact versions.

## Current state

- **Already exists:**
  - 47 Java files: auth (OTP via email, JWT, sessions), admin endpoints, offline wallet, devices, settlement, and the protocol classes.
  - Tests: `ProtocolTest`, `SettlementIntegrationTest`, plus `PhoneSimulator` for building fake devices, certificates and tokens.
- **Endpoints:**
  - `/auth/signup/*`, `/auth/login/*`, `/auth/refresh`, `/auth/logout`
  - `/offline/bank-public-key`
  - `/offline/devices`
  - `/offline/wallet` (plus `/load`, `/unload` and `/certificate`)
  - `/offline/sync`, `/offline/payments`
  - `/admin/*`: stats, accounts, devices, payments, security events
- **Not built yet:** everything in "Work to do" below.

## Work to do

### A. Security test suite (do this first)

The 19 attacks in `docs/SECURITY_TEST_PLAN.md` become JUnit tests.

- Put them in `src/test/java/com/offlinepay/offline/AttackTest.java`, or one class per section.
- Name each test after its attack number, for example `attack06_replayIsIdempotent`.
- Each test uses `PhoneSimulator`/`EcKeys`/`PaymentToken`, fires at `SettlementService.settle(...)` or at `/offline/sync` through MockMvc, and asserts two things: the rejection code, and that no money moved.
- Run the suite **before** the changes in B and record which tests fail. Attacks 12 and 14 are expected to get through today, and 15 and 19 aren't built yet.
- The before-and-after comparison is the key evidence in the report. Save the results to `docs/results/attack-results-before.md`, then `attack-results-after.md`.

### B. The five backend changes

These come from the security test plan. None of them changes the byte format.

1. **Settlement deadline on the server's clock** (fixes attack 14; also drives the release of unclaimed payments).
   - Reject with `SETTLEMENT_DEADLINE_PASSED` if the server receives the token more than 24 hours after `cert.expiresAt`, judged by the **server's** clock.
   - Reject with `TIMESTAMP_BEFORE_CERTIFICATE` if `token.timestamp < cert.issuedAt`.
   - Place these checks next to the certificate-consistency checks.
2. **Revocation list** (fixes attack 15).
   - Add a `revoked_certificates` table: serial, device id, revokedAt, reason.
   - Freezing a device (add `POST /offline/devices/{id}/freeze` for the owner; admin freeze already exists) revokes its current certificate.
   - Every sync response returns the serials revoked within the last 7 days, because older certificates have expired anyway.
   - At settlement, a payment signed **after** the freeze time from a revoked certificate is still credited to a receiver who had not synced since the freeze. The loss is recorded against the bank, capped at the offline balance, and the owner is refunded. If the receiver had already received the revocation list, reject with `CERTIFICATE_REVOKED`.
   - The liability table is in `docs/DESIGN_DECISIONS.md`.
3. **Hold money from flagged payments** (fixes attack 12).
   - Credits from payments flagged `DOUBLE_SPEND` or `OVERSPEND` go into a `heldKobo` amount on the receiving `User`, not the withdrawable balance, for 48 hours.
   - A scheduled job releases them afterwards.
   - Flag any account that receives from two or more frozen devices.
   - The receiver is still credited, so the guarantee holds.
4. **Record each device's hardware level** (narrows attacks 11 and 12).
   - `POST /offline/devices` accepts the attestation evidence: the Android key attestation chain, or an iOS App Attest object.
   - Store `hardwareLevel`: `STRONGBOX` (Secure Enclave counts here), `TEE`, `SOFTWARE` or `UNVERIFIED`.
   - Set the certificate limit by level:
     - StrongBox: ₦20,000
     - TEE: ₦10,000, configurable
     - Software, rooted or failed check: no offline certificate at all
   - For the prototype, verifying the chain against Google's attestation root is enough. Document it if full verification is skipped.
5. **Per-user rate limits** (fixes attack 19).
   - Use Bucket4j (pin the version) on `/offline/sync` and the `/auth/*` OTP endpoints.
   - Return 429 when the limit is hit.
   - The existing cap of 100 payments per sync stays.

### C. Unclaimed and interrupted payments

The full design is in `docs/DESIGN_DECISIONS.md`.

- Add `ON_HOLD` and `RELEASED` statuses for payments the payer reported as signed but which no receiver ever claimed.
- Add a `release_unclaimed` scheduled job. After `cert.expiresAt` plus 24 hours of grace, it releases the payer's unclaimed held amount back to their main balance at the next sync.
- The payer's sync must be able to upload its own signed-but-unconfirmed tokens. Either side's upload settles the payment.

### D. Things the report (Chapter 3) needs from the code

- Exact tool and library versions, from `pom.xml`. Keep them current.
- An ERD showing primary and foreign keys, and a definition for every table. Keep the JPA entities clean so the diagram can be generated from them.
- A full API endpoint table. Keep `README.md` up to date when endpoints change.
- A flowchart of the settlement checks. Keep the numbered `// N.` comments in `SettlementService` accurate.
- Performance numbers:
  - add a small benchmark test for settlement throughput (payments per second) and for sign/verify time in Java;
  - write results to `docs/results/`.

## How to work in this repo

- Build and test with `mvn test` (there is no Maven wrapper yet). All tests must pass before committing.
- Work on a branch per piece of work, for example `feat/attack-tests` or `feat/revocation`. Commit small, with clear messages. Open a PR to `main` when a piece is done.
- Every new rejection code goes in four places:
  - `SettlementResult`
  - the security-event log
  - `docs/PROTOCOL.md`, if it's visible to the app
  - the attack test that proves it
- Don't add features beyond this list without asking the owner. This is an assessed final-year project, and the scope is fixed by its objectives.
- Write code the owner can explain in a defence: readable, commented where the security reasoning isn't obvious, and with no clever tricks.

## Objectives this backend serves (from Chapter 1)

1. Design a compact ECDSA-signed token and certificate that fit in one QR code and can be verified offline.
2. Develop the cross-platform app. This is in the other repo.
3. **Develop the settlement server**: settle on reconnect, record each payment exactly once, and detect double-spend, overspend, replay and forgery. **This repo.**
4. Evaluate security (the 19 attacks), performance and usability. The attack tests and benchmarks live here.

The live planning docs are on claude.ai. The repo copies in `docs/` are what Claude Code should follow.
- Security test plan: https://claude.ai/artifact/PaXMQvejF8LTFzk5cDj1yk
- Lost phones, interrupted payments and device support: https://claude.ai/artifact/Af8URBwd2nYuCQDNaV5zYd
- Flutter build plan: https://claude.ai/artifact/YNWSW9oJtGPzysWyxmNPsg
