# Consensus Engine Vulnerabilities — Sub-Category Index

## Purpose
Index of all consensus-layer vulnerability skills. These target the core safety and liveness properties of blockchain consensus protocols.

## Scope
Consensus engine source code (Go, Rust, Java), validator logic, block finalization, quorum calculation, fork choice rules, and leader election mechanisms.

---

## Available Skills

| Skill | Protocol | Impact | Path |
|---|---|---|---|
| Insufficient Validator Threshold for Finality | QBFT / IBFT / BFT variants | Critical — Double Spend, Fork | `bft-validator-threshold/SKILL.md` |

---

## Routing Logic

```
What is the consensus mechanism?
│
├── BFT-based (QBFT, IBFT, Tendermint, HotStuff)?
│   │
│   ├── Quorum / threshold calculation bug?
│   │   └── → bft-validator-threshold/SKILL.md
│   │
│   └── Leader election / view change bug?
│       └── → [COMING SOON] bft-leader-election/SKILL.md
│
├── PoS (Ethereum, Cosmos)?
│   └── → [COMING SOON] pos-slashing/SKILL.md
│
└── PoW?
    └── → [COMING SOON] pow-selfish-mining/SKILL.md
```

---

## Reconnaissance Commands (Apply to Any Consensus Target)

```bash
# Find consensus engine files in Go projects
find . -type f -name "*.go" | xargs grep -l "ValidatorSet\|QuorumSize\|F()\|ByzantineFault" 2>/dev/null

# Find consensus engine files in Rust projects  
find . -type f -name "*.rs" | xargs grep -l "quorum\|threshold\|validator_set\|byzantine" 2>/dev/null

# Look for hardcoded thresholds (common misconfiguration)
grep -rn "2/3\|0\.67\|0\.66\|ceil.*validator\|floor.*validator" --include="*.go" --include="*.rs"

# Find block finalization / commit functions
grep -rn "Finalize\|Commit\|verifyCommit\|checkQuorum\|isQuorum" --include="*.go" --include="*.rs"
```

---

## Key Mathematical Properties to Verify in Any BFT System

| Property | Formula | What to Check in Code |
|---|---|---|
| Fault tolerance | `F = floor((N - 1) / 3)` | How is F computed? |
| Safety quorum | `Q = 2F + 1` | Is quorum compared with `>= 2F+1` or just `> F`? |
| Minimum validators | `N >= 3F + 1` | Is minimum enforced at genesis? |
| Round-change quorum | `Q_rc = F + 1` | Is round-change threshold separate from commit threshold? |