# Security Policy

Carapace is security software. We take reports seriously and appreciate
responsible disclosure.

## Reporting a vulnerability

**Do not open a public issue.** Report privately via
[GitHub private vulnerability reporting](../../security/advisories/new).

Please include:

- Affected component (`enclave`, `server`, `cli`, `web`, `infra`, `crypto`)
  and version or commit
- A description of the issue and its impact
- Steps to reproduce or a proof of concept

## What to expect

- Acknowledgement within 3 business days
- An initial assessment within 10 business days
- Coordinated disclosure within 90 days of the report, or sooner once a fix
  ships

## Scope

In scope: anything that lets a party other than the secret's owner obtain a
plaintext secret, use a secret outside its policy, forge or suppress receipts,
or cause a non-attested workload to decrypt data.

The trust assumptions and known residual risks are documented in
`docs/THREAT_MODEL.md`. Issues that only restate a documented residual risk
are out of scope, but ideas for reducing those risks are welcome.
