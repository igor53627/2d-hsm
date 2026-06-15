# AC#5 Layer-1 funding-gate PREDICATE — the SINGLE SOURCE of the gate formula (TASK-7.7 §5, TASK-16).
#
# Imported by BOTH `nixos-module.nix` (the build-time assertion) AND `flake.nix`
# `checks.agent-anti-rollback-gate` (the self-test), each applying it to its own inputs — so the two
# can never drift (review wf_a2cce791 mechanism B), AND the module derives the predicate from its OWN
# primitive args rather than trusting a passed/defaultable value (so a caller that evaluates the module
# directly cannot fail the gate open by omitting a derived flag — review job 7523 codex finding).
#
# Returns `true` when the build MAY pass; `false` when a productionMode FUNDING profile
# (`agentAntiRollbackEnabled`, derived from an installed faucet/transfer signer) is at mode "none"
# WITHOUT the audited residual opt-out — which the nixos-module assertion turns into a build failure.
{
  productionMode,
  agentAntiRollbackEnabled,
  agentAntiRollbackMode,
  antiRollbackResidualOptOut,
}:
!(productionMode && agentAntiRollbackEnabled && agentAntiRollbackMode == "none" && !antiRollbackResidualOptOut)
