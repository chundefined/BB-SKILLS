# DeFi — Skills

## Quick Recon
```bash
# Swap / trade functions (MEV / slippage candidates)
grep -rn "function.*swap\|function.*trade\|function.*exchange" --include="*.sol"

# Missing slippage protection
grep -rn "amountOutMin\|minAmountOut\|slippage\|deadline" --include="*.sol"

# Spot price (oracle manipulation / sandwich candidate)
grep -rn "getReserves\|getAmountOut\|getPrice\|calcPrice\|quote(" --include="*.sol"

# Oracle integrations
grep -rn "latestRoundData\|consult\|observe\|TWAP" --include="*.sol"

# Flash loan entry points
grep -rn "flashLoan\|flashSwap\|executeOperation\|uniswapV2Call\|onFlashLoan" --include="*.sol"
```

## Skills

| Skill | Target | Trigger pattern | Severity | File |
|---|---|---|---|---|
| Transaction Frontrunning & Sandwich Attack | AMM, DEX router, token swap | Swap function with no `minAmountOut` / `deadline`; spot price used; protocol auto-swaps with `amountOutMin = 0` | High → Critical | `frontrunning-sandwich-attack/SKILL.md` |
| Oracle Manipulation / Price Feed Attack *(coming soon)* | Any contract using `getReserves()` or single-block price | Spot price from AMM reserve used without TWAP within same tx | High–Critical | — |
| Flash Loan Economic Exploit *(coming soon)* | Lending protocols, AMMs | `flashLoan` / `flashSwap` entry points + price-sensitive logic in same tx | Critical | — |
| Liquidation Logic Flaw *(coming soon)* | Lending / margin protocols | Liquidation threshold, health factor calc, or collateral valuation errors | High–Critical | — |
