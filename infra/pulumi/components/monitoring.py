"""Alerting on changes that could widen who can decrypt (on by default).

The residual risk in the threat model is a project owner changing KMS IAM or
loosening the WIF gate. Both are Admin Activity audit log entries (always on),
so a log-match alert makes such a change visible within minutes. Decrypt
calls are Data Access entries, which the stack turns on for Cloud KMS; the
alert also fires on a decrypt by anyone other than the attested enclave.

The alert also watches its own blind spots: log routing (a sink exclusion
would drop the KMS entries before they are matched) and the project's alert
policies and notification channels. Deleting this policy cannot page anyone,
but the deletion stays in Cloud Audit Logs, and every other change to these
resources fires while the policy still exists.
"""

from __future__ import annotations

from collections.abc import Sequence

import pulumi
import pulumi_gcp as gcp

NOTIFICATION_RATE_LIMIT = "300s"
AUTO_CLOSE = "1800s"


def build_alert_filter(
    *,
    key_ring_name: str,
    project_number: str,
    pool_id: str,
    enclave_sa_email: str,
    enclave_sa_unique_id: str,
) -> str:
    """Log filter matching IAM or configuration changes to the decrypt path.

    Matching the key ring path covers the ring itself and every key in it.
    Service account audit entries name the account by email or unique ID
    depending on the method, so both are matched.
    """
    kms_change = (
        'protoPayload.serviceName="cloudkms.googleapis.com"'
        ' AND protoPayload.methodName=("SetIamPolicy" OR "CreateCryptoKeyVersion"'
        ' OR "ImportCryptoKeyVersion" OR "UpdateCryptoKeyPrimaryVersion")'
        f' AND protoPayload.resourceName:"{key_ring_name}"'
    )
    wif_change = (
        'protoPayload.serviceName="iam.googleapis.com"'
        f' AND protoPayload.resourceName:"workloadIdentityPools/{pool_id}"'
    )
    enclave_sa_change = (
        'protoPayload.serviceName="iam.googleapis.com"'
        f' AND (protoPayload.resourceName:"serviceAccounts/{enclave_sa_email}"'
        f' OR protoPayload.resourceName:"serviceAccounts/{enclave_sa_unique_id}")'
    )
    # Also catches a change to the project's audit config (for example turning
    # off the KMS Data Access logs), which is written through SetIamPolicy.
    project_iam_change = (
        'protoPayload.serviceName="cloudresourcemanager.googleapis.com"'
        ' AND protoPayload.methodName="SetIamPolicy"'
    )
    # Sinks, exclusions, log buckets and settings decide whether the KMS Data
    # Access entries below are ever ingested. Only writes are Admin Activity
    # entries, so the substrings match no read-only method.
    log_routing_change = (
        'protoPayload.serviceName="logging.googleapis.com"'
        ' AND protoPayload.methodName:("Sink" OR "Exclusion" OR "Bucket"'
        ' OR "Settings")'
    )
    alerting_change = (
        'protoPayload.serviceName="monitoring.googleapis.com"'
        ' AND protoPayload.methodName:("AlertPolicy" OR "NotificationChannel")'
    )
    # A Data Access entry (see kms.enable_kms_data_access_logs). The enclave
    # decrypts as a federated principal of this project's attestation pool;
    # any other caller, allowed or denied, is suspicious, including a
    # same-named pool in another project. An entry without a principal
    # subject also matches, which errs towards alerting.
    foreign_decrypt = (
        'protoPayload.serviceName="cloudkms.googleapis.com"'
        ' AND protoPayload.methodName="AsymmetricDecrypt"'
        f' AND protoPayload.resourceName:"{key_ring_name}"'
        " AND NOT protoPayload.authenticationInfo.principalSubject:"
        f'"/projects/{project_number}/locations/global'
        f'/workloadIdentityPools/{pool_id}/"'
    )
    clauses = (
        kms_change,
        wif_change,
        enclave_sa_change,
        project_iam_change,
        log_routing_change,
        alerting_change,
        foreign_decrypt,
    )
    return " OR ".join(f"({clause})" for clause in clauses)


def create_iam_change_alert(
    *,
    prefix: str,
    key_ring_name: pulumi.Input[str],
    project_number: pulumi.Input[str],
    pool_id: pulumi.Input[str],
    enclave_sa_email: pulumi.Input[str],
    enclave_sa_unique_id: pulumi.Input[str],
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
    log_filter = pulumi.Output.all(
        key_ring_name, project_number, pool_id, enclave_sa_email, enclave_sa_unique_id
    ).apply(
        lambda args: build_alert_filter(
            key_ring_name=args[0],
            project_number=args[1],
            pool_id=args[2],
            enclave_sa_email=args[3],
            enclave_sa_unique_id=args[4],
        )
    )
    return gcp.monitoring.AlertPolicy(
        f"{prefix}-decrypt-path-change",
        display_name="Carapace: decrypt-path IAM or configuration changed",
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
                "Someone changed IAM or configuration on the Carapace KMS key "
                "ring, the attestation WIF pool, the enclave service account, "
                "project IAM, log routing, or alerting, or a principal other "
                "than the attested enclave called AsymmetricDecrypt on the "
                "key. Confirm it was intended; an unexpected decrypter grant "
                "defeats the attestation gate, and a log exclusion or alert "
                "change can hide one."
            ),
            "mime_type": "text/markdown",
        },
    )
