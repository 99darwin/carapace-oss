"""Cloud KMS resource names shared by the enclave, server and clients.

The enclave reports its key as a full crypto key *version* resource name and
refuses envelopes wrapped under any other. The server advertises the same
name at ``/v1/kms/public-key``, so both sides validate against one pattern.
"""

from __future__ import annotations

import re

# projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/N, with
# GCP's project-id syntax and a positive version number. Every segment is
# bounded, so a match is always well under the 512-character storage limit.
KMS_KEY_VERSION_NAME = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]"
    r"/locations/[a-z0-9-]{1,63}"
    r"/keyRings/[A-Za-z0-9_-]{1,63}"
    r"/cryptoKeys/[A-Za-z0-9_-]{1,63}"
    r"/cryptoKeyVersions/[1-9][0-9]{0,18}$"
)


def is_kms_key_version_name(name: object) -> bool:
    """True only for a full ``.../cryptoKeyVersions/N`` resource name."""
    return isinstance(name, str) and KMS_KEY_VERSION_NAME.fullmatch(name) is not None
