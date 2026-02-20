# Bug Bounty Skills — Master Index

## Purpose
This is the root dispatcher for all bug bounty skills. Read this first to navigate to the correct sub-skill based on the target technology.

## How to Use This Skill Tree
1. Identify the **target category** from the table below.
2. Navigate to the corresponding `SKILL.md` index.
3. Read the category index to find the specific vulnerability skill.
4. Load the specific skill SKILL.md and execute its methodology.

> **Rule:** Always read the specific vulnerability SKILL.md before writing any report, payload, or analysis. Never rely on general knowledge alone.

---

## Skill Tree

```
bugbounty/
└── web3/                          ← Blockchain, DeFi, Smart Contracts, Consensus
    ├── consensus/                 ← BFT, PoS, PoW consensus engine vulnerabilities
    │   └── bft-validator-threshold/   ← Insufficient validator quorum
    ├── defi/                      ← AMMs, DEX, Lending, MEV, Economic Exploits
    │   └── frontrunning-sandwich-attack/ ← Tx frontrunning & sandwich attacks
    └── smart-contracts/           ← Solidity, Vyper, Rust/Anchor logic flaws
        ├── dos-unbounded-gas-loop/    ← DoS via unbounded loop gas consumption
        └── zero-address-validation/   ← Missing zero-address check → fund loss
```

---

## Target → Skill Routing Table

| Target Description | Category | Path |
|---|---|---|
| Blockchain network with BFT/QBFT/IBFT consensus | Web3 → Consensus | `web3/consensus/SKILL.md` |
| Solidity/EVM smart contract, gas DoS, loop vulnerability | Web3 → Smart Contracts | `web3/smart-contracts/SKILL.md` |
| Smart contract missing zero-address validation, fund loss to burn address | Web3 → Smart Contracts | `web3/smart-contracts/zero-address-validation/SKILL.md` |
| DeFi protocol, AMM, DEX, MEV, frontrunning, sandwich | Web3 → DeFi | `web3/defi/SKILL.md` |
| Smart contract logic flaws | Web3 | `web3/SKILL.md` |
| DeFi protocol, AMM, lending protocol | Web3 | `web3/SKILL.md` |
| Node software, P2P layer, mempool | Web3 | `web3/SKILL.md` |

---

## Trigger Conditions (When to Use Bug Bounty Skills)
- User provides a bug bounty target, scope, or codebase to audit.
- User asks to find vulnerabilities, write a PoC, or draft a report.
- User mentions a CVE, audit report, or security finding to replicate.

---

## Adding New Skills
When creating a new skill, follow this structure:
1. Create directory: `bugbounty/<category>/<subcategory>/<vuln-name>/SKILL.md`
2. Update the category index SKILL.md to list the new skill.
3. Update this root dispatcher routing table.