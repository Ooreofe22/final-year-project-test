# Security Test Plan: the 19 attacks

Each attack becomes a JUnit test named `attackNN_shortDescription`. Each test does the following:

- builds fake devices, certificates and tokens with `PhoneSimulator`, `EcKeys`, `PayerCertificate` and `PaymentToken`;
- fires the attack at `SettlementService.settle(...)`, or at `POST /offline/sync` through MockMvc for the server attacks;
- asserts the rejection code, **and that no money moved**.

Run the suite twice: once on the current code, and once after the five backend changes in `CLAUDE.md`. Record both runs in `docs/results/`. Use one row per attack, with these columns: expected result, actual result, pass or fail, and the STRIDE category.

17 of the 19 can be tested without the app. Attack 13 needs real phones, and attack 15 needs the revocation feature first.

## A. Forgery and replay

| # | Attack | How to run it | Expected result | Backend today |
|---|---|---|---|---|
| 1 | Fake bank certificate | Sign a certificate with a key that isn't the bank's | `FORGED_CERTIFICATE` | Handled |
| 2 | Change the amount after signing | Edit the amount bytes and keep the old signature | `TAMPERED_TOKEN` | Handled |
| 3 | Change who gets paid | Swap the receiver device ID and keep the signature | `TAMPERED_TOKEN` | Handled |
| 4 | Borrowed certificate | Attach device B's certificate to a payment signed by device A | `CERTIFICATE_DEVICE_MISMATCH` or `KEY_MISMATCH` | Handled |
| 5 | Over the limit | Sign ₦25,000 on a ₦20,000 certificate | `OVER_CERTIFICATE_LIMIT` | Handled |
| 6 | Replay | Submit the same payment twice | `ALREADY_SETTLED`; money moves once | Handled |
| 7 | Second form of the same signature | Rewrite the signature's s value as n − s (still valid) and resubmit | Same payment ID, so `ALREADY_SETTLED` | Handled: the ID hashes the payment without its signature |
| 8 | Stranger submits it | A third user submits someone else's payment | `NOT_A_PARTY` | Handled |
| 9 | Both sides sync at once | Two threads submit the same payment at the same moment | One `SETTLED`, one `ALREADY_SETTLED` | Handled by database locks |

## B. Overspending

| # | Attack | How to run it | Expected result | Backend today |
|---|---|---|---|---|
| 10 | Reused payment number | Two different payments with the same counter | `DOUBLE_SPEND`; phone frozen | Handled |
| 11 | Tampered app pays 5 sellers | 5 × ₦20,000 from a ₦20,000 reserve | The first settles; the others are flagged `OVERSPEND`; phone frozen | Handled, but the payer's main balance can go negative |
| 12 | Teaming up | A cheat pays an accomplice repeatedly; the accomplice withdraws at once | The accomplice's money is held for review | **Gets through: the bank loses the shortfall** |

## C. Time tricks

| # | Attack | How to run it | Expected result | Backend today |
|---|---|---|---|---|
| 13 | Phone clock set back | Change the date on a real phone to dodge the 7-day lock | The seller's phone rejects it with `CERTIFICATE_EXPIRED` (trusted clock) | The seller's phone checks its own clock. Needs real phones |
| 14 | Fake earlier date | After expiry, sign a payment stamped with a date inside the valid week | Rejected | **Gets through: the server trusts the payer's date** |

## D. Lost phones

| # | Attack | How to run it | Expected result | Backend today |
|---|---|---|---|---|
| 15 | Pay after the freeze | Freeze A, sync seller B, then A pays B | `CERTIFICATE_REVOKED` | Not built yet |

## E. The server itself

| # | Attack | How to run it | Expected result | Backend today |
|---|---|---|---|---|
| 16 | Fake or expired login token | Edit the JWT, or wait past its expiry | 401 | Check |
| 17 | Read someone else's data | Change an ID in the URL | 403 | Check |
| 18 | Guess the one-time code | Try codes repeatedly | Locked after `MAX_ATTEMPTS` | Handled |
| 19 | Flood the sync endpoint | Send 101 payments in one sync, then many requests per second | The first is rejected (100 cap); the second is slowed down (429) | Cap handled; per-user limit not built |

## The five backend changes these tests point to

| # | Change | Fixes attack | Where in the code |
|---|---|---|---|
| 1 | Settlement deadline based on the server's clock, and reject payments dated before `cert.issuedAt` | 14; also drives the release of unclaimed payments | `SettlementService`, next to the certificate checks |
| 2 | Revocation list | 15 | New `revoked_certificates` table, the sync response, and the seller-side verifier in the app |
| 3 | 48-hour hold on money from flagged payments | 12 | `SettlementService` after the fraud checks, plus a held amount on `User` |
| 4 | Record each phone's hardware level and set limits by level | 11 and 12 (narrows them) | Device sign-up in `OfflineWalletService` |
| 5 | Per-user request limits (Bucket4j) | 19 | A filter on `/offline/sync` and the auth endpoints |

## Reporting it in Chapter 4

- **Results table:** attack number, attack, expected result, actual result, and pass or fail. Use one row per attack.
- **STRIDE tags:**
  - forgery is Spoofing or Tampering;
  - replay is Repudiation;
  - flooding is Denial of service;
  - reading others' data is Information disclosure;
  - overspending is Elevation of privilege.
- **Evidence:** quote the security-event log entry for each rejection.
- **Honest limits:** attacks 11 and 12 assume a phone whose app has been broken into. Change 4 makes that harder but not impossible.
- **Coverage:** state how many of the 19 pass before the changes and how many pass after.
