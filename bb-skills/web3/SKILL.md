# Web3 Bug Bounty Skills — Category Index

## Purpose
Index of all Web3 / Blockchain security skills. Read this to find the right skill for your target.

## Scope of This Category
Any target involving: blockchain networks, consensus engines, smart contracts, DeFi protocols, bridges, oracles, node software, wallets, or any decentralized infrastructure.

---

## Available Sub-Categories

### Consensus Engine Vulnerabilities
**Path:** `consensus/SKILL.md`
**Use when:** Target is a blockchain node, validator network, or consensus protocol implementation.

| Vulnerability | Severity | Path |
|---|---|---|
| BFT Insufficient Validator Threshold | Critical | `consensus/bft-validator-threshold/SKILL.md` |

---

## Routing Logic

```
Is the vulnerability in...
│
├── Consensus / Finality / Validator logic?
│   └── → consensus/SKILL.md
│
├── Smart Contract (Solidity, Vyper, Rust/Anchor)?
│   └── → [COMING SOON] smart-contracts/SKILL.md
│
├── DeFi Protocol (AMM, lending, liquidation)?
│   └── → [COMING SOON] defi/SKILL.md
│
├── Bridge / Cross-chain?
│   └── → [COMING SOON] bridges/SKILL.md
│
└── Node / P2P / RPC?
    └── → [COMING SOON] node-layer/SKILL.md
```

---

## Key Concepts for Web3 Auditing
- **Finality:** A block is final when it cannot be reverted. BFT systems guarantee this with 2/3+ quorum.
- **Safety vs Liveness:** Safety = no two conflicting blocks finalized. Liveness = the chain keeps producing blocks.
- **Byzantine Fault:** A node that can behave arbitrarily (crash, lie, collude).
- **Quorum:** The minimum number of validators needed to reach consensus. For BFT: `2F + 1` where `F = floor((N-1)/3)`.