"""Optional alerting on changes that could widen who can decrypt.

The residual risk in the threat model is a project owner changing KMS IAM or
loosening the WIF gate. Both are Admin Activity audit log entries (always on),
so a log-match alert makes such a change visible within minutes.
"""

from __future__ import annotations

from collections.abc import Sequence

import pulumi
import pulumi_gcp as gcp

NOTIFICATION_RATE_LIMIT = "300s"
AUTO_CLOSE = "1800s"


def build_alert_filter(*, key_name: str, pool_name: str) -> str:
    """Log filter matching IAM or configuration changes to the decrypt path."""
    kms_change = (
        'protoPayload.serviceName="cloudkms.googleapis.com"'
        ' AND protoPayload.methodName=("SetIamPolicy" OR "CreateCryptoKeyVersion"'
        ' OR "ImportCryptoKeyVersion" OR "UpdateCryptoKeyPrimaryVersion")'
        f' AND protoPayload.resourceName:"{key_name}"'
    )
    wif_change = (
        'protoPayload.serviceName="iam.googleapis.com"'
        f' AND protoPayload.resourceName:"{pool_name}"'
    )
    project_iam_change = (
        'protoPayload.serviceName="cloudresourcemanager.googleapis.com"'
        ' AND protoPayload.methodName="SetIamPolicy"'
    )
    return f"({kms_change}) OR ({wif_change}) OR ({project_iam_change})"


def create_iam_change_alert(
    *,
    prefix: str,
    key_name: pulumi.Input[str],
    pool_name: pulumi.Input[str],
    emails: Sequence[str],
) -> gcp.monitoring.AlertPolicy:
    channels = [
        gcp.monitoring.NotificationChannel(
            f"{prefix}-alert-email-{index}",
            display_name=f"Carapace security alerts ({index})",
            type="email",
            labels={"email_address": email},
        )
        for index, email in enumerate(emails)
    ]
    log_filter = pulumi.Output.all(key_name, pool_name).apply(
        lambda args: build_alert_filter(key_name=args[0], pool_name=args[1])
    )
    return gcp.monitoring.AlertPolicy(
        f"{prefix}-decrypt-path-change",
        display_name="Carapace: KMS key, WIF pool or project IAM changed",
        combiner="OR",
        conditions=[
            {
                "display_name": "Decrypt-path configuration change",
                "condition_matched_log": {"filter": log_filter},
            }
        ],
        alert_strategy={
            "notification_rate_limit": {"period": NOTIFICATION_RATE_LIMIT},
            "auto_close": AUTO_CLOSE,
        },
        notification_channels=[channel.name for channel in channels],
        documentation={
            "content": (
                "Someone changed IAM or configuration on the Carapace KMS key, "
                "the attestation WIF pool, or project IAM. Confirm the change "
                "was intended; an unexpected decrypter grant defeats the "
                "attestation gate."
            ),
            "mime_type": "text/markdown",
        },
    )
