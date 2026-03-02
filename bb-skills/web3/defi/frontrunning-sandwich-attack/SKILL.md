---
name: bb-frontrunning-sandwich-attack
description: DeFi security skill for detecting and exploiting transaction frontrunning and sandwich attacks. Use when a target DeFi protocol, AMM, or DEX router executes token swaps with on-chain price calculation but lacks minAmountOut enforcement or deadline parameters. Covers recon grep patterns, slippage/deadline detection, profitability calculation, and mempool analysis. See references/ for full exploitation chain, evasion edge cases, report template, and scripts/ for Foundry PoC test.
---

# Skill: DeFi — Transaction Frontrunning and Sandwich Attacks

## 0. When to Use This Skill
Use this skill when **all** of the following are true:
- Target is a DeFi protocol, AMM, DEX router, or any smart contract that executes token swaps or trades.
- The contract calculates trade output at execution time based on current on-chain state (reserves, price).
- You are looking for MEV (Maximal Extractable Value) extraction vectors, price manipulation, or missing slippage protection.

**Skip this skill if:** The contract uses a fixed-price mechanism (e.g., fixed-rate token sale), implements commit-reveal schemes, or exclusively processes trades through private/encrypted mempools with no public visibility.

---

## 1. Meta-Data
- **Category:** Business Logic / MEV (Maximal Extractable Value)
- **Target Component:** Automated Market Makers (AMMs), Token Swap Functions, DEX Routers, DeFi Protocols
- **Complexity:** Medium — requires understanding of AMM mechanics, transaction ordering, and gas economics
- **Estimated CVSS:** 7.4 (High) when user funds are directly extractable (AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N)
- **Reference:** Flashbots MEV Taxonomy, Flash Boys 2.0 (Daian et al.), Ethereum is a Dark Forest (Dan Robinson)

---

## 2. Prerequisites (Trigger Conditions)
- [ ] The contract contains a function that executes trades or swaps based on a dynamic price (e.g., `getAmountOut()`, `getPrice()`, reserve-ratio calculation).
- [ ] The price/output amount is determined at the moment of execution rather than being pre-agreed by the user.
- [ ] The swap function lacks a user-specified minimum output parameter (`minAmountOut`, `amountOutMin`) or the parameter exists but is not enforced before the transfer.
- [ ] The function lacks a `deadline` parameter, or if present, allows excessively long windows (e.g., `block.timestamp + 1 year`).
- [ ] Transactions are submitted to a public mempool where they can be observed before inclusion in a block.
- [ ] The trade size is large enough relative to pool liquidity to produce meaningful price impact.

---

## 3. Reconnaissance & Detection

### 3.1 Locate Swap/Trade Functions

```bash
# Find swap and trade functions
grep -rn "function.*swap\|function.*trade\|function.*exchange\|function.*buy\|function.*sell" --include="*.sol"

# Find price calculation functions
grep -rn "getPrice\|getAmountOut\|getAmountIn\|getReserves\|calcOutput\|quote(" --include="*.sol"

# Find functions that interact with AMM pools
grep -rn "IUniswapV2Pair\|IUniswapV2Router\|ISwapRouter\|IPancakeRouter\|ICurvePool" --include="*.sol"

# Find token transfer patterns within swap functions
grep -rn -A10 "function.*swap" --include="*.sol" | grep -E "\.transfer\(|\.transferFrom\(|safeTransfer"
```

### 3.2 Check for Slippage Protection

```bash
# Search for slippage parameters in function signatures
grep -rn "minAmountOut\|amountOutMin\|amountOutMinimum\|minOutput\|maxAmountIn\|maxPrice\|slippage" --include="*.sol"

# Search for require/assert statements that enforce slippage
grep -rn "require.*>=.*min\|require.*<=.*max\|require.*amount.*Out" --include="*.sol"

# Find swap functions WITHOUT slippage parameters (likely vulnerable)
grep -rn "function.*swap.*(" --include="*.sol" | grep -v "min\|max\|slippage\|deadline"
```

### 3.3 Check for Deadline Protection

```bash
# Look for deadline enforcement
grep -rn "deadline\|expiry\|validUntil\|block\.timestamp" --include="*.sol"

# Find modifier or require patterns for deadlines
grep -rn "require.*deadline\|require.*block.timestamp\|modifier.*ensure\|modifier.*expired" --include="*.sol"
```

### 3.4 Check for Private/Protected Submission Paths

```bash
# Look for commit-reveal patterns (MEV-resistant)
grep -rn "commit\|reveal\|hash.*order\|sealed\|encrypted" --include="*.sol"

# Look for batch auction / frequent batch patterns
grep -rn "batch\|auction\|CoWSwap\|CrocSwap\|settl" --include="*.sol"

# Look for access control on swap functions (private relayer only)
grep -rn "onlyRelayer\|onlyKeeper\|onlyAuthorized\|trustedForwarder" --include="*.sol"
```

### 3.5 Vulnerability Decision Table

| Pattern Found | MEV Risk | Vulnerable? |
|---|---|---|
| Swap function with no `minAmountOut` and no `deadline` | Fully exposed — attacker controls price and timing | **YES — High** |
| Swap function with `minAmountOut` but no enforcement (`require`) | Parameter exists but is cosmetic | **YES — High** |
| Swap function with `minAmountOut = 0` hardcoded or defaulted | Slippage protection is nullified | **YES — High** |
| Swap function with user-supplied `minAmountOut` enforced + no `deadline` | Partial protection — stale tx can be exploited later | **YES — Medium** |
| Swap function with `minAmountOut` enforced + `deadline` enforced | Standard protection — residual MEV within slippage tolerance | **Low risk** |
| Swap via commit-reveal or batch auction mechanism | Transaction content hidden from mempool | **No** — MEV-resistant |
| Swap via private mempool / Flashbots Protect only | Not visible in public mempool | **Low risk** |

---

## 4. Next Steps

All detailed exploitation, PoC code, evasion edge cases, and report templates are in `references/` and `scripts/`:

| File | Contents |
|---|---|
| `references/exploitation.md` | Full exploitation chain: profitability math, mempool monitoring, frontrun/backrun sequence, code evidence |
| `references/evasion.md` | Gas price auctions, private pools, multi-hop routing, state-dependent price edge cases |
| `references/report-template.md` | Bug bounty report template with impact, steps to reproduce, and fix recommendations |
| `scripts/SandwichAttackTest.sol` | Foundry test — proves sandwich attack profitability and that slippage protection blocks it |

```bash
# Run the PoC Foundry test:
forge test --match-contract SandwichAttackTest -vvv
```

> **References:** Flashbots MEV Docs, Flash Boys 2.0 (arxiv:1904.05234), SWC-120,
> Uniswap V2 amountOutMin Pattern, MEV Blocker.
