# DeFi Protocol Vulnerabilities — Sub-Category Index

## Purpose
Index of all DeFi (Decentralized Finance) protocol vulnerability skills. These target economic exploits, MEV vectors, oracle manipulation, and protocol logic flaws in on-chain financial primitives.

## Scope
DeFi protocol source code (Solidity, Vyper), AMM mechanics, lending/borrowing protocols, liquidation engines, oracle integrations, token swap logic, yield aggregators, and any protocol where economic value flows through smart contract logic.

---

## Available Skills

| Skill | Target | Impact | Path |
|---|---|---|---|
| Transaction Frontrunning & Sandwich Attacks | AMMs, Token Swaps, DEX Routers | High — Direct User Fund Extraction | `frontrunning-sandwich-attack/SKILL.md` |

---

## Routing Logic

```
What is the DeFi vulnerability class?
│
├── MEV / Transaction Ordering Exploitation?
│   │
│   ├── Frontrunning or sandwich attack on swaps?
│   │   └── → frontrunning-sandwich-attack/SKILL.md
│   │
│   └── Backrunning / liquidation MEV?
│       └── → [COMING SOON]
│
├── Oracle Manipulation / Price Feed Attack?
│   └── → [COMING SOON] oracle-manipulation/SKILL.md
│
├── Flash Loan Economic Exploit?
│   └── → [COMING SOON] flash-loan/SKILL.md
│
├── Lending / Liquidation Logic Flaw?
│   └── → [COMING SOON] liquidation-logic/SKILL.md
│
└── Yield / Reward Calculation Error?
    └── → [COMING SOON] reward-miscalculation/SKILL.md
```

---

## Reconnaissance Commands (Apply to Any DeFi Target)

```bash
# Find all Solidity files in the project
find . -type f -name "*.sol" 2>/dev/null

# Find swap/trade functions
grep -rn "function.*swap\|function.*trade\|function.*exchange" --include="*.sol"

# Find price calculation functions
grep -rn "getPrice\|getAmountOut\|getReserves\|calcPrice\|quote(" --include="*.sol"

# Find slippage protection parameters
grep -rn "minAmountOut\|maxAmountIn\|amountOutMin\|slippage\|deadline" --include="*.sol"

# Find oracle integrations
grep -rn "latestRoundData\|getLatestPrice\|consult\|observe\|TWAP" --include="*.sol"

# Find flash loan interfaces
grep -rn "flashLoan\|flashSwap\|executeOperation\|uniswapV2Call\|onFlashLoan" --include="*.sol"

# Find token transfer patterns (value flow)
grep -rn "\.transfer(\|\.transferFrom(\|safeTransfer\|safeTransferFrom" --include="*.sol"

# Find liquidity pool interactions
grep -rn "addLiquidity\|removeLiquidity\|mint(\|burn(" --include="*.sol"
```

---

## Key Concepts for DeFi Auditing

| Concept | Description |
|---|---|
| **AMM (Automated Market Maker)** | A smart contract that holds token reserves and uses a mathematical formula (e.g., `x * y = k`) to determine trade prices. Trades move the price along the curve. |
| **Slippage** | The difference between the expected price and the actual execution price. In AMMs, large trades move the price, causing slippage. Without protection, attackers exploit this. |
| **MEV (Maximal Extractable Value)** | Profit extracted by reordering, inserting, or censoring transactions within a block. Validators and searchers compete for MEV. |
| **Sandwich Attack** | A specific MEV strategy: frontrun a victim's trade to move the price, let the victim trade at the worse price, then backrun to profit from the price movement. |
| **TWAP (Time-Weighted Average Price)** | An oracle mechanism that averages price over time to resist single-block manipulation. More resistant to flash loans than spot prices. |
| **Flash Loan** | An uncollateralized loan that must be repaid within the same transaction. Used to amplify capital in economic exploits. |
| **Price Impact** | The percentage change in token price caused by a trade. Larger trades in smaller pools have greater price impact. |
| **Deadline Parameter** | A timestamp after which a pending transaction should revert. Prevents stale transactions from being executed at unfavorable prices. |
