# AC#5 Layer-1 funding-gate PREDICATE — the SINGLE SOURCE of the gate formula (TASK-7.7 §5, TASK-16).
#
# Imported by BOTH `nixos-module.nix` (the build-time assertion) AND `flake.nix`
# `checks.agent-anti-rollback-gate` (the self-test), each applying it to its own inputs — so the two
# can never drift (review wf_a2cce791 mechanism B), AND the module derives the predicate from its OWN
# primitive args rather than trusting a passed/defaultable value (so a caller that evaluates the module
# directly cannot fail the gate open by omitting a derived flag — review job 7523 codex).
#
# FAIL-CLOSED BY ALLOWLIST (review compact job 7539): a productionMode FUNDING build
# (`agentAntiRollbackEnabled`, derived from an installed faucet/transfer signer) passes ONLY when the
# audited residual opt-out is recorded OR the mode is EXACTLY one of the sanctioned mechanisms
# {remote-counter, external-ledger}. Any OTHER mode value — "none", a typo, the §5-forbidden standalone
# "operator-signed-boot", or any unvalidated string a DIRECT `nixos-module.nix` consumer passes
# (bypassing `guest-profile.nix`'s enum `throw`) — FAILS the gate. (Keying on `== "none"` alone would
# let an unrecognised non-"none" string pass on the direct path.)
#
# Returns `true` when the build MAY pass; `false` ⇒ the nixos-module assertion turns it into a build
# failure. ("operator-signed-boot" is deliberately NOT in the allowlist — §3 it is replay-vulnerable
# alone, only a challenge-response sub-mode of remote-counter, never a standalone passing mode.)
{
  productionMode,
  agentAntiRollbackEnabled,
  agentAntiRollbackMode,
  antiRollbackResidualOptOut,
}:
(!productionMode)
|| (!agentAntiRollbackEnabled)
|| antiRollbackResidualOptOut
|| (agentAntiRollbackMode == "remote-counter")
|| (agentAntiRollbackMode == "external-ledger")
