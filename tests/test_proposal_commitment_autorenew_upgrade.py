from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from pulpo.commerce import DomainPurchaseRequest, DomainQuote, assess_quote
from pulpo.proposal_commitment import ProposalCommitmentViolation, SQLiteProposalCommitments


NOW = 81_000_000


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: object) -> str:
    return sha256(canonical(value)).hexdigest()


class ProposalCommitmentAutoRenewUpgradeTests(unittest.TestCase):
    def test_pre_fix_commitment_cannot_gain_new_auto_renew_meaning_after_restart(self) -> None:
        request = DomainPurchaseRequest(
            request_id="legacy-autorenew-proposal-v0",
            principal="agent:hostile-worker-sandbox-v0",
            acceptable_domains=("pulpo-legacy-autorenew.example",),
            max_purchase_cents=2_000,
            max_renewal_cents=2_400,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember/namecom-sandbox",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
            auto_renew_enabled=False,
        )
        quote = DomainQuote(
            quote_id="legacy-autorenew-quote-v0",
            domain="pulpo-legacy-autorenew.example",
            registrar="name.com",
            purchase_price_cents=2_000,
            renewal_price_cents=2_400,
            owner_ref=request.owner_ref,
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 50_000,
        )
        assessment = assess_quote(
            request,
            quote,
            credential_ref="credential://name-com/sandbox-executor",
            now_ns=NOW,
        )
        self.assertIsNotNone(assessment.order)
        current_order = assessment.order

        # Reconstruct the exact pre-fix request material: auto-renew did not
        # exist in the governed request, so it was absent from request_hash.
        legacy_request = asdict(request)
        legacy_request.pop("auto_renew_enabled")
        legacy_request_hash = digest(legacy_request)
        self.assertNotEqual(legacy_request_hash, request.request_hash)

        # Reconstruct the pre-fix order material as it would have been stored:
        # it carried the old request hash and had no auto-renew field at all.
        legacy_order = asdict(current_order)
        legacy_order["request_hash"] = legacy_request_hash
        legacy_order.pop("auto_renew_enabled")
        legacy_order_hash = digest(legacy_order)
        self.assertNotEqual(legacy_order_hash, current_order.order_hash)

        availability_hash = "a" * 64
        created_at_ns = NOW
        expires_at_ns = current_order.expires_at_ns
        material = {
            "schema": "pulpo.proposal-commitment.v0",
            "order_hash": legacy_order_hash,
            "availability_hash": availability_hash,
            "created_at_ns": created_at_ns,
            "expires_at_ns": expires_at_ns,
        }
        commitment_hash = digest(material)
        commitment_id = f"proposal:{commitment_hash}"

        with TemporaryDirectory() as directory:
            path = Path(directory) / "proposal.sqlite3"
            SQLiteProposalCommitments(path)  # create the current durable schema
            with sqlite3.connect(path) as connection:
                connection.execute(
                    """
                    INSERT INTO proposal_commitments
                        (commitment_id, commitment_hash, order_hash, availability_hash,
                         order_json, created_at_ns, expires_at_ns, state)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'ready')
                    """,
                    (
                        commitment_id,
                        commitment_hash,
                        legacy_order_hash,
                        availability_hash,
                        canonical(legacy_order).decode(),
                        created_at_ns,
                        expires_at_ns,
                    ),
                )

            # Restart/current code decodes the legacy JSON with the new safe
            # default False, which necessarily changes the canonical action
            # object. The persisted old hash must therefore invalidate the
            # commitment instead of silently granting it the new meaning.
            restarted = SQLiteProposalCommitments(path)
            with self.assertRaisesRegex(
                ProposalCommitmentViolation,
                "proposal_order_hash_mismatch",
            ):
                restarted.claim(commitment_id, now_ns=NOW + 1)

            # Failed upgrade validation must not consume or rewrite the legacy
            # commitment; it remains inert and requires a fresh trusted proposal.
            with sqlite3.connect(path) as connection:
                state = connection.execute(
                    "SELECT state FROM proposal_commitments WHERE commitment_id = ?",
                    (commitment_id,),
                ).fetchone()[0]
            self.assertEqual("ready", state)


if __name__ == "__main__":
    unittest.main()
