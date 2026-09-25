"""Carapace: minimal, attestation-gated self-host deployment on GCP."""

import pulumi

from components.config import load_config
from components.stack import deploy

for name, value in deploy(load_config()).items():
    pulumi.export(name, value)
