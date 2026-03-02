# Bug Bounty Report Template — Frontrunning & Sandwich Attack

## Title
`[High] MEV: Missing Slippage Protection in <function_name>() Enables Transaction Frontrunning and Sandwich Attacks`

## Summary
The `<function_name>()` function in `<file_path>` executes token swaps using a price calculated at execution time via `<price_function>()` without requiring the user to specify a minimum acceptable output amount (`minAmountOut`) or a transaction deadline. An attacker monitoring the public mempool can sandwich the victim's transaction by:
1. Frontrunning with a large trade to shift the price unfavorably.
2. Allowing the victim's trade to execute at the worse price.
3. Backrunning to reverse their position and extract the price difference as profit.

This results in direct financial loss for every user of the swap function proportional to their trade size and the pool's liquidity depth.

## Impact
- **Direct fund extraction:** Users receive fewer tokens than they would at the fair market price. Losses scale with trade size relative to pool liquidity.
- **Systematic exploitation:** MEV bots continuously monitor the mempool and will exploit every unprotected swap automatically.
- **Protocol credibility damage:** Users experiencing consistently worse execution will abandon the protocol.
- **Compounding with protocol swaps:** If the protocol itself calls `<function_name>()` internally (e.g., for auto-compounding or rebalancing), protocol-owned funds are also at risk.

## Severity
**High** — CVSS 7.4 (AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N)

Escalates to **Critical** if the protocol performs automated swaps with hardcoded `minAmountOut = 0` (CVSS 8.6).

## Steps to Reproduce
1. Deploy the vulnerable contract on a local fork (e.g., `forge test --fork-url <RPC>`).
2. Observe that `<function_name>()` accepts only `amountIn` with no `minAmountOut` or `deadline` parameter.
3. Simulate a victim's swap transaction of `<amount>` tokens.
4. Submit a frontrunning transaction with a higher gas price that executes the same swap function with a larger amount, shifting the price.
5. Observe the victim's transaction executes at a worse price, receiving fewer tokens than the fair-market output.
6. Submit a backrunning transaction that reverses the attacker's position for a net profit.
7. Run the provided Foundry PoC: `forge test --match-test test_sandwichAttack -vvv`

## Recommended Fix
1. **Required:** Add a `amountOutMin` parameter that the user must set, enforced with `require(amountOut >= amountOutMin)` before executing the transfer.
2. **Required:** Add a `deadline` parameter enforced with `require(block.timestamp <= deadline)` to prevent stale transactions from being held and executed later at an unfavorable price.
3. **Optional:** Use a TWAP oracle instead of spot price to reduce single-block manipulation effectiveness.
4. **Optional:** Implement a commit-reveal scheme for high-value trades to hide trade intent from the mempool.

---

## References
- [Flashbots — MEV Taxonomy and Documentation](https://docs.flashbots.net/)
- [Ethereum is a Dark Forest — Dan Robinson & Georgios Konstantopoulos (Paradigm)](https://www.paradigm.xyz/2020/08/ethereum-is-a-dark-forest)
- [Escaping the Dark Forest — samczsun](https://samczsun.com/escaping-the-dark-forest/)
- [Flash Boys 2.0: Frontrunning in Decentralized Exchanges (Daian et al.)](https://arxiv.org/abs/1904.05234)
- [Uniswap V2 Router — amountOutMin Pattern](https://docs.uniswap.org/contracts/v2/reference/smart-contracts/router-02)
- [SWC-120: Weak Sources of Randomness / Transaction Ordering Dependence](https://swcregistry.io/docs/SWC-120)
- [MEV Blocker — Protecting Users from MEV](https://mevblocker.io/)
