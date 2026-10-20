"""One-shot non-authority acceptance probe for the exact Pulpo HSM signer.

This module does not issue an approval envelope or mutate Pulpo authority state.
It signs one domain-separated acceptance payload with the already-selected exact
Google Cloud KMS CryptoKeyVersion and relies on the canonical signer to verify
the returned HSM signature locally before emitting evidence.
"""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Any

from .gcp_kms_transport import GoogleCloudKmsTransport
from .kms_signer import GoogleCloudKmsP256Signer

KEY_VERSION_NAME = (
    "projects/dulcet-opus-499511-a5/locations/us-west1/"
    "keyRings/pulpo-authority/cryptoKeys/approval-signer/cryptoKeyVersions/1"
)
EXPECTED_PUBLIC_FINGERPRINT = (
    "b59288317ee9735a3bfd24595fd6a5d5c97476c1461b945124aded9ffd0ab127"
)
PROBE_PAYLOAD = (
    b"pulpo.kms.acceptance.v1\x00"
    b"NON_AUTHORITY_TEST_VECTOR\x00"
    b"approval-signer/cryptoKeyVersions/1"
)


def probe_kms_signer(
    transport: Any | None = None,
    *,
    expected_fingerprint: str = EXPECTED_PUBLIC_FINGERPRINT,
) -> dict[str, object]:
    """Perform one exact non-authority HSM sign/verify operation."""

    signer = GoogleCloudKmsP256Signer(
        transport or GoogleCloudKmsTransport(),
        key_version_name=KEY_VERSION_NAME,
        authority_id="authority:kms-acceptance-probe",
        verifier_id="verifier:gcp-hsm-acceptance-probe",
        key_id="key:approval-signer:v1",
        expected_key_fingerprint=expected_fingerprint,
    )
    signature = signer.sign(PROBE_PAYLOAD)
    signature_bytes = bytes.fromhex(signature)

    return {
        "schema": "pulpo.authority-kms-acceptance.v1",
        "key_version": KEY_VERSION_NAME,
        "kms_algorithm": signer.kms_algorithm,
        "protection_level": signer.protection_level,
        "public_key_fingerprint_sha256": signer.key_fingerprint,
        "probe_payload_sha256": sha256(PROBE_PAYLOAD).hexdigest(),
        "signature_hex": signature,
        "signature_sha256": sha256(signature_bytes).hexdigest(),
        "signature_bytes": len(signature_bytes),
        "local_signature_verification": True,
        "authority_effect": "none",
    }


def main() -> int:
    print(json.dumps(probe_kms_signer(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
