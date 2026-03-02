# Evasion Techniques & Edge Cases — Frontrunning / Sandwich

## 6.1 Gas Price Auction (Priority Gas Auction — PGA)
If the victim increases their gas price to get faster inclusion, the attacker must respond with an even higher gas price. This creates a bidding war that can erode the attacker's profit margin but does not eliminate the vulnerability.

## 6.2 Private Transaction Pools
Attackers use private relayers (Flashbots Protect, MEV Blocker, etc.) to hide their frontrun/backrun transactions from the public mempool. This prevents counter-sandwiching by other MEV searchers.

## 6.3 Multi-Hop Routing Attacks
Even if individual pools have slippage protection, a multi-hop route (A→B→C) can be sandwiched at each hop if the intermediate slippage bounds are loose.

## 6.4 State-Dependent Price Calculation
Even if the price is calculated after a state change within the same function, the vulnerability persists because the attacker's frontrun alters the on-chain state *before* the victim's transaction begins execution.

```solidity
// STILL VULNERABLE: State update before price calc doesn't help
function swapTokens(uint256 amountIn) public {
    balances[msg.sender] -= amountIn;         // State change first
    uint256 price = getPrice();                // Price still reads manipulated reserves
    uint256 amountOut = amountIn * price / 1e18;
    balances[msg.sender] += amountOut;
}
```

## 6.5 Protocol-Level Swaps (autoCompound, Rebalance)
Protocol-internal functions that perform swaps on behalf of the protocol (e.g., auto-compounding yield, rebalancing collateral) are high-value MEV targets because they often hardcode `minAmountOut = 0` and are called on predictable schedules.

## 6.6 Cross-DEX Arbitrage Amplification
Attacker can amplify profit by simultaneously manipulating price across multiple DEXs that share liquidity or reference each other's prices.
