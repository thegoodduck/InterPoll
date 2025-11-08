# InterPoll — Verifiable, Private, Tamper‑Evident Voting

InterPoll is a modern, privacy‑first voting platform designed to make community decisions—and national elections—trustworthy, transparent, and resilient. It combines strong cryptography, open audit trails, and simple UX to deliver a system your voters can understand and your auditors can verify.

## What problem does it solve?

- Low trust: People worry votes can be changed or lost.
- Duplicate voting: One person can sometimes vote multiple times.
- Opaque systems: Results arrive without a way for citizens to verify them.
- Privacy risks: Data often includes personally identifiable information.

## What’s our promise?

- One person, one (or controlled) vote: Multiple layers make it hard to vote twice.
- Receipts without exposing choices: Voters get a cryptographic receipt proving inclusion, not identity.
- End‑to‑end verifiability: Anyone can verify that their vote was counted and the public tally matches.
- Privacy by default: Sensitive data is minimized and encrypted at rest.

## How it works (plain English)

1. A voter signs in (e.g., Google, Microsoft, Idena) or anonymously if allowed by the poll.
2. The system checks signals (account, network, device) to reduce duplicates.
3. When a vote is cast, we store only what’s necessary: the choice and a timestamp—no raw IPs.
4. The vote is sealed with modern encryption and added to an append‑only transparency log.
5. The log is anchored to a global timestamping network (OpenTimestamps), making tampering detectable.
6. The voter gets a receipt, and we can auto‑push it to a neutral “Receipter” service for extra assurance.

## Why it’s hard to cheat

- Multi‑layer duplicate defense: account tag, IP tag, legacy device evidence, optional location proof, cookie & session age guard.
- Session age gating: You can require a session to be at least N minutes old before voting (thwarts “drive‑by” mass voting).
- Configurable strict mode: Tightens checks when integrity is paramount.
- Planned: Browser/device fingerprint and time‑window rate limiting for even stronger protection.

## Why voters can trust it

- Receipts: Every voter gets a file hash that uniquely matches their vote’s contents. They can verify inclusion independently.
- Public, tamper‑evident log: Anyone can recompute the chain of entries. Any change would break the chain.
- Independent timestamping: We anchor chain heads using OpenTimestamps, adding external proof of time and integrity.
- Open by design: Plain‑language docs and optional open‑sourcing enable community oversight.

## Why officials can trust it

- Encryption at rest: Databases, logs, chain heads, and vote payload files are encrypted by default with AES‑GCM.
- Minimal personal data: Only pseudonymous tags are stored (e.g., HMACs); raw IPs/locations are not retained.
- Defense in depth: Multiple signals reduce duplicates without collecting sensitive identifiers.
- Clear audit trail: Private audit logs (server‑only) can correlate signals for investigations without exposing choices.

## Administrator controls

- Allow multiple votes per poll (for surveys) or enforce one‑vote per person (for elections).
- Require login by provider(s) or allow anonymous.
- Require a minimum session age before voting.
- Enforce Receipter submission so every receipt is independently escrowed.
- Configure cookie policies for third‑party/embedded contexts.

## Demo script (5 minutes)

1. Create a poll with options and parameters (login required, session age 60 minutes, strict dedup on).
2. Log in as a voter and attempt to vote twice—second attempt is blocked by duplicate defenses.
3. Cast a valid vote and show the receipt page; demonstrate automatic Receipter push.
4. Open the public results; refresh to show live counts.
5. Verify: Use the receipt hash to check the transparency log and the on‑disk vote file.
6. Prove tamper evidence: Show that any edit would break the chain and fail verification.

## What makes InterPoll different

- Verifiability you can explain: Cryptographic receipts and a visible chain—no black boxes.
- Practical privacy: Store less, encrypt the rest. No raw IPs; optional location hashing.
- Incremental security: Start simple, turn on strict mode as your stakes rise.
- Deployment flexibility: Run on a single VM or scale out; works offline with periodic timestamp anchoring.

## Roadmap highlights

- Device fingerprint (privacy‑preserving) and rate limiting for stronger duplicate prevention.
- Key rotation tool and migration CLI for encrypted archives.
- Formal test suite and third‑party audits.
- Optional external identity providers and zero‑knowledge upgrades.

---

# Technical appendix (for evaluators)

- Crypto: AES‑GCM for encryption at rest; HMAC‑SHA256 for pseudonymous tags; SHA‑256 for content addressing.
- Transparency log: Hash‑chained entries; heads anchored with OpenTimestamps. Any change is detectable.
- Receipts: File hash of the voter’s encrypted payload—verifiable without revealing identity or choice linkage.
- Dedup logic: Priority order (account > IP > legacy device > optional location > cookie > session age). Strict mode available.
- Cookies: SameSite configurable; Secure enforced when third‑party usage is enabled.
- Compliance: Minimal PII by design; retention policy configurable via environment flags.

## Operating notes

- Set DATA_ENCRYPTION_KEY to enable encryption. Keep this secret and rotate periodically.
- Enable ENFORCE_RECEIPTER to require escrow before leaving the receipt page.
- Tune DEFAULT_MIN_SESSION_AGE_MINUTES and per‑poll overrides to your risk tolerance.
- Back up the `votes/` directory and `chain_head*` files regularly; treat keys and logs as sensitive.

Contact us to pilot InterPoll in your city, union, or organization. Together, let’s make every vote verifiable, private, and trusted.