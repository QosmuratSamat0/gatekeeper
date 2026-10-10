# AUTH-05 email verification threat model

Scope: registration delivery, authenticated resend, public token confirmation.

| STRIDE category | Asset / boundary and threat | Mitigation | Residual risk |
|---|---|---|---|
| Spoofing | Attacker submits guessed email addresses to cause messages or probe ownership. | Resend requires a live Bearer session; accepts no caller-supplied address; fixed response for verified/cooldown states; per-account cooldown. | Registration already returns duplicate-account status; mailbox ownership is only as strong as access to that mailbox. |
| Tampering | Caller changes the token or races multiple confirmations to verify an unintended account. | 256-bit random token, SHA-256 digest lookup, account-bound row, strict validation, account-then-token locks, one transaction and single active token. | A compromised database writer can alter account flags directly. |
| Repudiation | Attacker denies a verification/resend attempt or operator logs expose the token. | Request IDs and safe event categories only; never log email body, recipient, token or SMTP credentials. | Metadata in reverse-proxy or mail-provider logs remains subject to their retention/access controls. |
| Information disclosure | Database or SMTP logs expose a raw token, recipient or password; SMTP traffic is intercepted. | Persist digest only; plain-text token sent only over mandatory validated STARTTLS; authenticate after TLS; redact message data and SMTP errors. | The mailbox provider and recipient mailbox necessarily see the token; mailbox compromise permits verification. |
| Denial of service | Repeated requests overload SMTP or prevent the user from receiving valid messages. | Authenticated resend, database-backed cooldown, bounded request body, per-IP confirmation limiter, bounded SMTP deadlines and connection cleanup. | Distributed account takeover can still consume outbound mail quota; no external abuse service is added. |
| Elevation of privilege | An attacker replays an expired/used token or exploits confirmation concurrency. | Short expiry, digest-only lookup, one-time consume, state recheck after locks, atomic account update; verification grants no roles or extra permissions. | Existing login policy intentionally allows unverified accounts; email verification is not a login factor. |

Relevant OWASP ASVS areas: V2 Authentication, V3 Session Management (existing session behavior must remain unchanged), V4 Access Control (resend identity), V7 Error Handling and Logging, V8 Data Protection, V9 Communications, V10 Malicious Code/Abuse protections. Map exact ASVS version/control IDs during Gemini implementation-plan review rather than guessing IDs.

Tests: replay/expiry/unknown-token response equivalence; account-owner-only resend; database cooldown under concurrency; simultaneous confirmation with one winner; SMTP STARTTLS/certificate/auth ordering; timeout and secret-redaction checks; no login-policy or JWT/session regression.
