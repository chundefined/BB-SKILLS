# Consensus — Skills

## Quick Recon
```bash
# Quorum / threshold logic (Go)
grep -rn "ValidatorSet\|QuorumSize\|F()\|ByzantineFault\|quorum\|threshold" --include="*.go"

# Quorum / threshold logic (Rust)
grep -rn "quorum\|threshold\|validator_set\|byzantine" --include="*.rs"

# Hardcoded threshold values (misconfiguration)
grep -rn "2/3\|0\.67\|0\.66\|ceil.*validator\|floor.*validator" --include="*.go" --include="*.rs"

# Block finalization entry points
grep -rn "Finalize\|Commit\|verifyCommit\|checkQuorum\|isQuorum" --include="*.go" --include="*.rs"
```

## Skills

| Skill | Protocol | Trigger pattern | Severity | File |
|---|---|---|---|---|
| Insufficient Validator Threshold for Finality | QBFT, IBFT, Tendermint, HotStuff | Commit-phase quorum check uses `<= F()` or `> F` instead of `>= 2F+1`; safety quorum not correctly enforced at finalization | Critical (double-spend, fork) | `bft-validator-threshold/SKILL.md` |
| BFT Leader Election / View Change Bug *(coming soon)* | QBFT, IBFT, Tendermint | Leader selection or view-change round threshold incorrectly computed | High–Critical | — |
| PoS Slashing Condition Bypass *(coming soon)* | Ethereum PoS, Cosmos | Validator can double-vote or equivocate without triggering slashing | Critical | — |
