"""Shared authentication — verification, credential resolution, OIDC flows.

Public API:
  resolve_auth          — coupled builder: token + matching verifier in one step
  ResolvedCredential    — token + verifier + source, from resolve_auth()
  TokenVerifier         — concrete JWKS-based JWT verifier
  TokenVerifierPort     — structural protocol: verify(str) → LayerActor
  TokenVerificationError — crypto verification failure
  IdentityClaimsError   — token verified but identity mapping failed
  AuthResolutionError   — raised when no credential can be resolved
  CredentialStore       — protocol for credential persistence backends
  verifier_for_token    — build a verifier from an existing token's issuer
  build_verifier_config — resolve verifier config from env/args (REST callers)
  DeviceCodeFlow        — interactive token acquisition (CLI)
  ClientCredentialsFlow — service-account (machine) token acquisition
  RefreshFlow           — refresh token exchange
  EmployeeDirectory     — protocol: is_active(identity) → status string
  ScriptDirectory       — directory backed by LEDGER_DIRECTORY_COMMAND
  load_directory        — the deployment's directory from env, or None
  apply_directory       — cross-check a verified human actor, stamp/refuse
  DirectoryRefusedError / DirectoryUnavailableError
"""

from traust_ledger.auth.claims import IdentityClaimsError, claims_to_actor
from traust_ledger.auth.config import (
    AuthResolutionError,
    CredentialStore,
    ResolvedCredential,
    build_verifier_config,
    resolve_auth,
    verifier_for_token,
)
from traust_ledger.auth.directory import (
    DirectoryRefusedError,
    DirectoryUnavailableError,
    EmployeeDirectory,
    ScriptDirectory,
    apply_directory,
    load_directory,
)
from traust_ledger.auth.flows import (
    ClientCredentialsFlow,
    DeviceCodeFlow,
    RefreshFlow,
)
from traust_ledger.auth.verifier import (
    TokenVerificationError,
    TokenVerifier,
    TokenVerifierPort,
    VerifierConfig,
)

__all__ = [
    "AuthResolutionError",
    "ClientCredentialsFlow",
    "CredentialStore",
    "DeviceCodeFlow",
    "DirectoryRefusedError",
    "DirectoryUnavailableError",
    "EmployeeDirectory",
    "IdentityClaimsError",
    "RefreshFlow",
    "ResolvedCredential",
    "ScriptDirectory",
    "TokenVerificationError",
    "TokenVerifier",
    "TokenVerifierPort",
    "VerifierConfig",
    "apply_directory",
    "build_verifier_config",
    "claims_to_actor",
    "load_directory",
    "resolve_auth",
    "verifier_for_token",
]
