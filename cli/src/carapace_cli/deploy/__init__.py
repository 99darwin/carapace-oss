"""``carapace deploy`` and ``carapace destroy``: self-hosting on GCP.

See docs/design/deploy.md. The heavy dependencies (Pulumi, google-auth,
sigstore) are the optional extra ``carapace-cli[deploy]`` and are imported
only when a deploy actually runs.
"""
