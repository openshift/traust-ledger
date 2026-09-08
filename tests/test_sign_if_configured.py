"""Write-path signing: sign_if_configured / stamp_and_sign.

Wired 2026-08-12 per ledger-integrity-remediation-plan P4. Until then nothing
in any write path invoked the signer — signing existed only in the
sign_merkle_root.py CLI — so 0 of 22,206 corpus layers were signed.

These tests pin the behaviour that matters BEFORE a key is provisioned: an
unconfigured signer is a silent no-op (so wiring is safe), and a configured
but broken signer is never silent.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traust_ledger._internal.integrity import (
    sign_if_configured,
    stamp_and_sign,
    stamp_merkle_metadata,
)
from traust_ledger._internal.integrity.signing import SigningConfig


def _layer(n=1):
    return {
        "metadata": {},
        "events": [
            {
                "event_id": f"e{i}",
                "finding_ref": f"F-{i}",
                "recorded_at": "2026-01-01T00:00:00Z",
                "source": {},
                "disposition": {},
                "rationale": "r",
            }
            for i in range(n)
        ],
    }


def test_unconfigured_is_a_silent_noop():
    """The state the harness is in until a key is provisioned. Wiring the
    call site must not break any writer while the key is unset."""
    L = _layer()
    attempt = stamp_and_sign(L)
    assert attempt.status == "unconfigured"
    assert attempt.configured is False
    assert attempt.error is None
    assert L["metadata"]["merkle_root"], "stamping must still happen"
    assert "merkle_root_signature" not in L["metadata"]


def test_configured_but_broken_reports_failed_and_writes_nothing():
    """A configured-but-failing signer must not degrade to silence — that is
    how a ledger ends up unsigned while everyone believes it is signed."""
    L = _layer()
    cfg = SigningConfig(method="keypair", key_path="/nonexistent/key.pem")
    stamp_and_sign(L)  # stamp first
    attempt = sign_if_configured(L, cfg)
    assert attempt.status == "failed"
    assert attempt.configured is True
    assert attempt.error
    assert "NOT signed" in (attempt.warning() or "")
    assert "merkle_root_signature" not in L["metadata"]


def test_signing_before_stamping_is_refused():
    """The signature covers the stamped metadata, so signing an unstamped
    layer would sign a stale/absent root."""
    cfg = SigningConfig(method="keypair", key_path="/nonexistent/key.pem")
    attempt = sign_if_configured({"metadata": {}, "events": []}, cfg)
    assert attempt.status == "failed"
    assert "stamp_merkle_metadata" in (attempt.error or "")


def test_identity_without_a_token_is_unconfigured_not_interactive():
    """A batch writer must never fall into an interactive OIDC flow."""
    L = _layer()
    stamp_and_sign(L)
    attempt = sign_if_configured(L, SigningConfig(method="identity", oidc_token=None))
    assert attempt.status == "unconfigured"
    assert attempt.method == "identity"


def test_stamp_and_sign_stamps_at_current_leaf_format():
    L = _layer(3)
    stamp_and_sign(L)
    assert L["metadata"]["leaf_format"] == 2
    assert L["metadata"]["merkle_size"] == 3


# --- stale-signature drop (2026-08-17) -------------------------------------
#
# A signature covers one root. When the events change, the stored signature
# stops describing the layer, and leaving it there is worse than having none: a
# verifier cannot tell a present-but-invalid signature from tampering. Found on
# 9 layers a 5.0 embargo backfill appended to with no key configured.


def _signed_layer(n=1):
    """Stamped, then hand-signed — the state the 2026-08-14 bulk pass left."""
    layer = _layer(n)
    stamp_merkle_metadata(layer)
    layer["metadata"]["merkle_root_signature"] = "MEUCIQD-fake-signature"
    layer["metadata"]["merkle_signing_method"] = "keypair"
    layer["metadata"]["merkle_signature_format"] = "sigstore-bundle"
    return layer


def _append_event(layer):
    layer["events"].append(
        {
            "event_id": "e-new",
            "finding_ref": "F-new",
            "recorded_at": "2026-08-17T00:00:00Z",
            "source": {},
            "disposition": {},
            "rationale": "r",
        }
    )


def test_stamp_drops_the_signature_when_the_root_moves():
    L = _signed_layer()
    old_root = L["metadata"]["merkle_root"]
    _append_event(L)

    dropped = stamp_merkle_metadata(L)

    assert dropped is True
    assert L["metadata"]["merkle_root"] != old_root
    for key in ("merkle_root_signature", "merkle_signing_method", "merkle_signature_format"):
        assert key not in L["metadata"], key


def test_stamp_keeps_a_signature_the_root_still_matches():
    """A re-stamp that changes nothing must not de-attest the layer."""
    L = _signed_layer()

    dropped = stamp_merkle_metadata(L)

    assert dropped is False
    assert L["metadata"]["merkle_root_signature"] == "MEUCIQD-fake-signature"
    assert L["metadata"]["merkle_signing_method"] == "keypair"


def test_stamp_and_sign_reports_the_drop_when_it_cannot_re_sign():
    L = _signed_layer()
    _append_event(L)

    attempt = stamp_and_sign(L)  # no LAAS_SIGNING_KEY_PATH in the env

    assert attempt.status == "unconfigured"
    assert attempt.stale_signature_dropped is True
    assert "UNSIGNED" in attempt.warning()


def test_warning_is_none_on_a_clean_unconfigured_write():
    """The pre-P8 normal case stays quiet — nothing was lost."""
    attempt = stamp_and_sign(_layer())

    assert attempt.status == "unconfigured"
    assert attempt.stale_signature_dropped is False
    assert attempt.warning() is None
