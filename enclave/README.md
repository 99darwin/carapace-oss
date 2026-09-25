# carapace-enclave

The code that runs inside the Confidential Space VM.

- `carapace_enclave.egress`: the generic credential-injecting executor. It
  validates an agent's HTTP request against a secret's injection policy,
  resolves DNS once and connects to the pinned public IP, injects the secret,
  and redacts it from the response.

Attestation, KMS unwrapping, the HTTP server, and receipts land in later PRs.
