"""Reviewed py_webauthn adapter; credential enrollment is intentionally absent."""

from __future__ import annotations

from webauthn import verify_authentication_response
from webauthn.helpers import parse_authentication_credential_json
from webauthn.helpers.structs import CredentialDeviceType

from .core import CeremonyResult, CredentialRecord


class PyWebAuthnVerifier:
    def verify(
        self,
        assertion: str,
        *,
        expected_challenge: bytes,
        expected_origin: str,
        expected_rp_id: str,
        credential: CredentialRecord,
    ) -> CeremonyResult:
        parsed = parse_authentication_credential_json(assertion)
        if parsed.id != credential.credential_id:
            raise ValueError("assertion credential does not match selected credential")
        verification = verify_authentication_response(
            credential=parsed,
            expected_challenge=expected_challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential.public_key,
            credential_current_sign_count=credential.sign_count,
            require_user_verification=True,
        )
        multi_device = verification.credential_device_type == CredentialDeviceType.MULTI_DEVICE
        return CeremonyResult(
            credential_id=parsed.id,
            user_present=True,
            user_verified=True,
            backup_eligible=multi_device,
            backed_up=verification.credential_backed_up,
            new_sign_count=verification.new_sign_count,
        )
