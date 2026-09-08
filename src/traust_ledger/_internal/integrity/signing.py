"""Signing backend adapters for Merkle root signatures."""

from __future__ import annotations

import abc
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


def _sigstore_importable() -> bool:
    """True when sigstore is installed or injected (e.g. test mocks in sys.modules)."""
    if "sigstore" in sys.modules:
        return sys.modules["sigstore"] is not None
    try:
        return importlib.util.find_spec("sigstore") is not None
    except (ImportError, ValueError):
        return False


#: Prefixes read for every signing setting, in order. `LAAS_` is current;
#: `HARNESS_` is the pre-extraction name and is still honoured because dropping it
#: was silent and fail-OPEN: 0.11.0 renamed the family with no alias, so a caller
#: exporting HARNESS_SIGNING_KEY_PATH (the harness, its migrations, every operator
#: runbook and CI job) suddenly configured NO signer and wrote unsigned layers —
#: while HARNESS_SIGNING_REQUIRED=1, the guard meant to catch exactly that, stopped
#: being read by the same rename. A renamed fail-closed switch defaults to off.
_ENV_PREFIXES = ("LAAS_SIGNING_", "HARNESS_SIGNING_")


def signing_env(suffix: str, default: str | None = None) -> str | None:
    """First set value across the supported prefixes, else `default`."""
    for prefix in _ENV_PREFIXES:
        value = os.environ.get(prefix + suffix)
        if value is not None:
            return value
    return default


@dataclass
class SignResult:
    signature: str  # base64-encoded signature or JSON bundle (OIDC)
    success: bool
    error: str | None = None


@dataclass
class VerifyResult:
    valid: bool
    error: str | None = None


@dataclass
class SigningConfig:
    """Config-driven signing dispatch. Loadable from env vars or a config dict."""

    method: str = "keypair"  # "keypair" | "identity"
    key_path: str | None = None
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    expected_identity: str | None = None
    oidc_token: str | None = None
    allow_interactive: bool = False
    ca_url: str | None = None
    tlog_url: str | None = None

    @classmethod
    def from_env(cls) -> SigningConfig:
        return cls(
            method=signing_env("METHOD", "keypair"),
            key_path=signing_env("KEY_PATH"),
            oidc_issuer=signing_env("OIDC_ISSUER"),
            oidc_client_id=signing_env("OIDC_CLIENT_ID"),
            expected_identity=signing_env("EXPECTED_IDENTITY"),
            oidc_token=signing_env("OIDC_TOKEN"),
            allow_interactive=signing_env("OIDC_INTERACTIVE", "0") == "1",
            ca_url=signing_env("CA_URL"),
            tlog_url=signing_env("TLOG_URL"),
        )


class SigningBackend(abc.ABC):
    """Abstract signing backend. Implementations wrap specific tools."""

    @property
    @abc.abstractmethod
    def method_name(self) -> str:
        """Generic method identifier (e.g. 'keypair', 'identity')."""
        ...

    @abc.abstractmethod
    def available(self) -> bool:
        """Check if this backend's tooling is available."""
        ...

    @abc.abstractmethod
    def sign(self, payload: bytes, key_path: str, *, rekor: bool = False) -> SignResult:
        """Sign payload bytes, return base64 signature."""
        ...

    @abc.abstractmethod
    def verify(self, payload: bytes, signature: str, key_path: str) -> VerifyResult:
        """Verify a base64 signature against payload."""
        ...


def _transparency_evidence(bundle: dict) -> list[str]:
    """Names of any transparency-log/timestamp material found in a bundle.

    Empty list == the signature was not published anywhere. Used as a
    post-condition on signing; see CosignBackend.sign.
    """
    vm = bundle.get("verificationMaterial") or {}
    found = []
    if vm.get("tlogEntries"):
        found.append(f"{len(vm['tlogEntries'])} tlogEntries")
    stamps = (vm.get("timestampVerificationData") or {}).get("rfc3161Timestamps")
    if stamps:
        found.append(f"{len(stamps)} rfc3161Timestamps")
    return found


class CosignBackend(SigningBackend):
    """Cosign sign-blob / verify-blob adapter."""

    @property
    def method_name(self) -> str:
        return "keypair"

    def available(self) -> bool:
        return shutil.which("cosign") is not None

    # cosign v3 compatibility (2026-08-12).
    #
    # v3 changed the sign-blob contract this backend targeted under v2:
    #   * --output-signature is deprecated and now HARD-FAILS ("must specify
    #     --bundle with --new-bundle-format"); the signature is delivered
    #     inside a Sigstore bundle written to a file, not on stdout.
    #   * --tlog-upload=false is rejected while the default signing config is
    #     active, and WITHOUT it cosign uploads to the PUBLIC rekor.sigstore.dev
    #     by default. For an internal security ledger that is unacceptable: it
    #     publishes the timing of ledger writes to an irrevocable public log,
    #     makes signing depend on Sigstore's availability, and inflates the
    #     bundle from ~390 bytes to ~3.8 KB (about 84 MB across a 22k-layer
    #     corpus). --use-signing-config=false restores the offline path.
    #
    # Also fixed here: the v2 code piped the payload on stdin but never passed
    # the positional blob argument, so every invocation failed with "requires
    # at least 1 arg(s), only received 0" — keypair signing had never worked.
    def sign(self, payload: bytes, key_path: str, *, rekor: bool = False) -> SignResult:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            blob = td_path / "payload.bin"
            bundle = td_path / "out.bundle"
            with blob.open("wb") as fh:
                fh.write(payload)

            cmd = ["cosign", "sign-blob", "--key", key_path, "--yes"]
            if not rekor:
                cmd.extend(["--use-signing-config=false", "--tlog-upload=false"])
            cmd.extend(["--bundle", bundle, blob])

            try:
                result = subprocess.run(cmd, capture_output=True, timeout=60)
            except (OSError, subprocess.SubprocessError) as e:
                return SignResult(signature="", success=False, error=str(e))

            if result.returncode != 0:
                return SignResult(
                    signature="",
                    success=False,
                    error=result.stderr.decode(errors="replace").strip(),
                )
            try:
                raw = Path(bundle).read_text(encoding="utf-8").strip()
            except OSError as e:
                return SignResult(
                    signature="",
                    success=False,
                    error=f"cosign reported success but wrote no bundle: {e}",
                )

        if not raw:
            return SignResult(signature="", success=False, error="cosign wrote an empty bundle")

        try:
            bundle = json.loads(raw)
        except ValueError:
            bundle = None

        # POST-CONDITION: never return a signature that was published.
        #
        # The flags above ask cosign not to use a transparency log, but flags
        # are not a durable defence — v2's `--tlog-upload=false` is REJECTED by
        # v3's default signing config, and v3 publishes to the PUBLIC
        # rekor.sigstore.dev when not told otherwise. A future version can
        # change the contract again. So instead of trusting the request, verify
        # the artifact: if the bundle carries a transparency-log entry or an
        # RFC3161 timestamp and logging was not explicitly requested, DISCARD
        # the signature and fail loudly. Publication is irreversible; a failed
        # signing run is not.
        #
        # Policy of record: config/external-tools.yaml, cosign
        # signing_policy.transparency_log: forbidden.
        if bundle is not None and not rekor:
            published = _transparency_evidence(bundle)
            if published:
                return SignResult(
                    signature="",
                    success=False,
                    error=(
                        "REFUSING the signature: cosign published it to a "
                        f"transparency log ({', '.join(published)}) despite "
                        "being asked not to. The signature has been "
                        "discarded, but the upload is already public and "
                        "irreversible. cosign has almost certainly changed "
                        "its flag contract again — see the "
                        "transparency-log hazard note on the cosign entry "
                        "in config/external-tools.yaml."
                    ),
                )

        # Compact to one line so it round-trips through JSON layer metadata.
        if bundle is not None:
            raw = json.dumps(bundle, separators=(",", ":"))
        return SignResult(signature=raw, success=True)

    def verify(self, payload: bytes, signature: str, key_path: str) -> VerifyResult:
        """Verify a v3 bundle, falling back to a v2 bare signature.

        Anything signed before the v3 port carries a base64 signature rather
        than a bundle, so both are accepted on the read path — refusing them
        would invalidate history that was validly signed under the old
        contract.
        """
        is_bundle = signature.lstrip().startswith("{")
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            blob = td_path / "payload.bin"
            with blob.open("wb") as fh:
                fh.write(payload)

            if is_bundle:
                bundle = td_path / "in.bundle"
                bundle.write_text(signature, encoding="utf-8")
                # --insecure-ignore-tlog is correct here rather than a
                # weakening: the bundle deliberately carries no
                # transparency-log entry (see sign). Integrity comes from the
                # key, not from Rekor.
                cmd = [
                    "cosign",
                    "verify-blob",
                    "--key",
                    key_path,
                    "--bundle",
                    bundle,
                    "--insecure-ignore-tlog",
                    blob,
                ]
            else:
                cmd = ["cosign", "verify-blob", "--key", key_path, "--signature", signature, blob]

            try:
                result = subprocess.run(cmd, capture_output=True, timeout=60)
            except (OSError, subprocess.SubprocessError) as e:
                return VerifyResult(valid=False, error=str(e))

        if result.returncode != 0:
            return VerifyResult(valid=False, error=result.stderr.decode(errors="replace").strip())
        return VerifyResult(valid=True)


class SigstoreOIDCBackend(SigningBackend):
    """OIDC/keyless signing backend using sigstore-python.

    Token acquisition follows the sigstore CLI convention:
      1. Explicit token (oidc_token / LAAS_SIGNING_OIDC_TOKEN)
      2. Ambient CI detection (detect_credential)
      3. Interactive OAuth2 via Issuer (opens browser, any OIDC provider)

    The `key_path` parameter in sign()/verify() is unused; identity
    verification uses `expected_identity` and `oidc_issuer` instead.
    """

    def __init__(
        self,
        oidc_issuer: str | None = None,
        oidc_client_id: str | None = None,
        expected_identity: str | None = None,
        oidc_token: str | None = None,
        allow_interactive: bool = False,
        ca_url: str | None = None,
        tlog_url: str | None = None,
    ) -> None:
        self._oidc_issuer = oidc_issuer
        self._oidc_client_id = oidc_client_id
        self._expected_identity = expected_identity
        self._oidc_token = oidc_token
        self._allow_interactive = allow_interactive
        self._ca_url = ca_url
        self._tlog_url = tlog_url

    @property
    def method_name(self) -> str:
        return "identity"

    def available(self) -> bool:
        return _sigstore_importable()

    def _validate_custom_urls(self) -> str | None:
        """Return an error string if custom URL config is invalid, else None."""
        has_ca = bool(self._ca_url)
        has_tlog = bool(self._tlog_url)
        if has_ca != has_tlog:
            return (
                "both ca_url and tlog_url must be configured for custom "
                "infrastructure (got ca_url={ca}, tlog_url={tlog})".format(
                    ca=self._ca_url or "<unset>",
                    tlog=self._tlog_url or "<unset>",
                )
            )
        return None

    def _build_signing_context(self):
        """Build a SigningContext targeting custom or default infrastructure."""
        from sigstore.models import ClientTrustConfig
        from sigstore.sign import SigningContext

        if self._ca_url and self._tlog_url:
            trust_config = ClientTrustConfig.from_json(
                f'{{"fulcio_url": "{self._ca_url}", "rekor_url": "{self._tlog_url}"}}'
            )
        else:
            trust_config = ClientTrustConfig.production()
        return SigningContext.from_trust_config(trust_config)

    def _build_verifier(self):
        """Build a Verifier targeting custom or default infrastructure."""
        from sigstore.verify import Verifier

        if self._ca_url and self._tlog_url:
            from sigstore.models import ClientTrustConfig

            trust_config = ClientTrustConfig.from_urls(
                fulcio_url=self._ca_url,
                rekor_url=self._tlog_url,
            )
            return Verifier(trust_config=trust_config)
        return Verifier.production()

    def _interactive_token(self):
        """Acquire an IdentityToken via interactive OAuth2 browser flow.

        Uses sigstore's Issuer class, which works with any OIDC provider
        that publishes .well-known/openid-configuration.
        """
        from sigstore.oidc import Issuer

        issuer = Issuer(self._oidc_issuer) if self._oidc_issuer else Issuer.production()

        kwargs: dict = {}
        if self._oidc_client_id:
            kwargs["client_id"] = self._oidc_client_id

        return issuer.identity_token(**kwargs)

    def _resolve_identity_token(self):
        """Resolve an IdentityToken from the configured sources.

        Falls through: explicit token -> ambient CI -> interactive OAuth2.
        Explicit token errors propagate (caller needs to know).
        Ambient/interactive errors fall through silently.
        """
        from sigstore.oidc import IdentityToken, detect_credential

        client_id = self._oidc_client_id or "sigstore"

        if self._oidc_token:
            return IdentityToken(self._oidc_token, client_id=client_id)

        try:
            raw = detect_credential()
            if raw:
                return IdentityToken(raw, client_id=client_id)
        except Exception:
            pass

        if self._allow_interactive:
            return self._interactive_token()

        return None

    def sign(self, payload: bytes, key_path: str, *, rekor: bool = False) -> SignResult:
        if not _sigstore_importable():
            return SignResult(
                signature="",
                success=False,
                error="sigstore package not installed — install with: pip install sigstore",
            )

        url_err = self._validate_custom_urls()
        if url_err:
            return SignResult(signature="", success=False, error=url_err)

        try:
            identity_token = self._resolve_identity_token()
            if identity_token is None:
                return SignResult(
                    signature="",
                    success=False,
                    error="No OIDC token available — set LAAS_SIGNING_OIDC_TOKEN, "
                    "run in a CI environment with ambient credentials, or "
                    "enable interactive mode (LAAS_SIGNING_OIDC_INTERACTIVE=1)",
                )

            ctx = self._build_signing_context()
            with ctx.signer(identity_token) as signer:
                bundle = signer.sign_artifact(payload)

            return SignResult(signature=bundle.to_json(), success=True)

        except Exception as e:
            error_msg = str(e) or type(e).__name__
            return SignResult(
                signature="",
                success=False,
                error=f"Signing failed ({type(e).__name__}): {error_msg}",
            )

    def verify(self, payload: bytes, signature: str, key_path: str) -> VerifyResult:
        try:
            from sigstore.models import Bundle
            from sigstore.verify import policy
        except ImportError:
            return VerifyResult(
                valid=False,
                error="sigstore package not installed — install with: pip install sigstore",
            )

        url_err = self._validate_custom_urls()
        if url_err:
            return VerifyResult(valid=False, error=url_err)

        try:
            bundle = Bundle.from_json(signature)
        except Exception as e:
            return VerifyResult(valid=False, error=f"Failed to deserialize signing bundle: {e}")

        try:
            if not self._expected_identity or not self._oidc_issuer:
                return VerifyResult(
                    valid=False,
                    error="OIDC verification requires expected_identity and "
                    "oidc_issuer to be configured",
                )

            identity_policy = policy.Identity(
                identity=self._expected_identity,
                issuer=self._oidc_issuer,
            )

            verifier = self._build_verifier()
            verifier.verify_artifact(payload, bundle, identity_policy)
            return VerifyResult(valid=True)

        except Exception as e:
            error_str = str(e)
            return VerifyResult(valid=False, error=error_str)


_METHOD_BACKENDS: dict[str, type[SigningBackend]] = {
    "keypair": CosignBackend,
    "identity": SigstoreOIDCBackend,
}


def get_backend(name: str = "cosign") -> SigningBackend:
    """Factory for signing backends by provider name."""
    providers: dict[str, type[SigningBackend]] = {
        "cosign": CosignBackend,
        "sigstore-oidc": SigstoreOIDCBackend,
    }
    cls = providers.get(name)
    if cls is None:
        raise ValueError(f"Unknown signing backend: {name!r}. Available: {list(providers)}")
    return cls()


def get_backend_for_method(method: str) -> SigningBackend:
    """Resolve a generic signing method name to the corresponding backend."""
    cls = _METHOD_BACKENDS.get(method)
    if cls is None:
        raise ValueError(
            f"Unknown signing method: {method!r}. Available methods: {list(_METHOD_BACKENDS)}"
        )
    return cls()


def get_backend_from_config(config: SigningConfig) -> SigningBackend:
    """Dispatch to the correct backend based on a SigningConfig."""
    cls = _METHOD_BACKENDS.get(config.method)
    if cls is None:
        raise ValueError(
            f"Unknown signing method: {config.method!r}. "
            f"Available methods: {list(_METHOD_BACKENDS)}"
        )
    if cls is SigstoreOIDCBackend:
        return cls(
            oidc_issuer=config.oidc_issuer,
            oidc_client_id=config.oidc_client_id,
            expected_identity=config.expected_identity,
            oidc_token=config.oidc_token,
            allow_interactive=config.allow_interactive,
            ca_url=config.ca_url,
            tlog_url=config.tlog_url,
        )
    return cls()
