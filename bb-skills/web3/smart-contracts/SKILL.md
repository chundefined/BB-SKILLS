# Smart Contract Vulnerabilities — Sub-Category Index

## Purpose
Index of all smart contract vulnerability skills. These target logic flaws, state manipulation, and economic exploits in on-chain programs (Solidity, Vyper, Rust/Anchor).

## Scope
Smart contract source code (Solidity, Vyper, Rust), EVM bytecode, transaction calldata, storage layout, gas mechanics, and contract interaction patterns.

---

## Available Skills

| Skill | Language | Impact | Path |
|---|---|---|---|
| DoS via Unbounded Gas Consumption in Loops | Solidity | High — Permanent Function Lockout | `dos-unbounded-gas-loop/SKILL.md` |
| Missing Zero-Address Validation | Solidity | High — Irreversible Fund Loss | `zero-address-validation/SKILL.md` |

---

## Routing Logic

```
What is the smart contract vulnerability class?
│
├── Denial of Service (DoS) / Gas exhaustion?
│   │
│   ├── Unbounded loop over dynamic array?
│   │   └── → dos-unbounded-gas-loop/SKILL.md
│   │
│   └── Other gas griefing patterns?
│       └── → [COMING SOON]
│
├── Input Validation (missing checks, zero address)?
│   │
│   ├── Missing zero-address check on critical address setters?
│   │   └── → zero-address-validation/SKILL.md
│   │
│   └── Other input validation issues?
│       └── → [COMING SOON]
│
├── Reentrancy (external call + state change)?
│   └── → [COMING SOON] reentrancy/SKILL.md
│
├── Access Control (missing auth, privilege escalation)?
│   └── → [COMING SOON] access-control/SKILL.md
│
├── Integer Overflow / Underflow?
│   └── → [COMING SOON] integer-overflow/SKILL.md
│
├── Oracle Manipulation / Price Feed Attack?
│   └── → [COMING SOON] oracle-manipulation/SKILL.md
│
├── Flash Loan / Economic Exploit?
│   └── → [COMING SOON] flash-loan/SKILL.md
│
└── MEV / Frontrunning / Sandwich Attack?
    └── → ../defi/SKILL.md (different sub-category)
```

---

## Reconnaissance Commands (Apply to Any Smart Contract Target)

```bash
# Find all Solidity files in the project
find . -type f -name "*.sol" 2>/dev/null

# Find contracts with loops over dynamic arrays
grep -rn "for\s*(.*\.length" --include="*.sol"

# Find external/public functions that modify state arrays
grep -rn "\.push(" --include="*.sol"

# Find payable functions (potential value at risk)
grep -rn "function.*payable" --include="*.sol"

# Find transfer/send/call patterns (fund movement)
grep -rn "\.transfer(\|\.send(\|\.call{value:" --include="*.sol"

# Find common OpenZeppelin imports (understand security baseline)
grep -rn "import.*@openzeppelin" --include="*.sol"
```

---

## Key Concepts for Smart Contract Auditing

| Concept | Description |
|---|---|
| **Block Gas Limit** | Maximum gas a single block can consume (~30M on Ethereum mainnet). Any transaction exceeding this always reverts. |
| **Storage (SSTORE/SLOAD)** | Most expensive EVM operations. Writing a new storage slot costs 20,000 gas; reading costs 2,100 gas. |
| **Pull vs Push Pattern** | Pull = users claim individually (safe). Push = contract iterates and sends to all (DoS-prone). |
| **Reentrancy** | External calls can re-enter the calling contract before state is updated. |
| **tx.origin vs msg.sender** | `tx.origin` is the EOA that initiated the transaction; `msg.sender` is the immediate caller. |
| **Proxy Patterns** | Delegatecall-based upgradeability can introduce storage collision and initialization bugs. |
