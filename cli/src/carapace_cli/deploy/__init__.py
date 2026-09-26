"""``carapace deploy`` and ``carapace destroy``: self-hosting on GCP.

See docs/design/deploy.md. The Python dependencies (google-auth, sigstore)
are the optional extra ``carapace-cli[deploy]`` and are imported only when
a deploy actually runs. Pulumi runs as the ``pulumi`` CLI, not a library.
"""
