# Skill: Smart Contract — Missing Zero-Address Validation (Irreversible Fund Loss)

## 0. When to Use This Skill
Use this skill when **all** of the following are true:
- Target is a Solidity smart contract deployed on an EVM-compatible chain (Ethereum, Polygon, BSC, Arbitrum, etc.).
- The contract accepts `address` parameters in functions that configure critical recipients (beneficiaries, owners, fee collectors, token addresses, vaults).
- Those address parameters are used in subsequent fund transfers (`transfer`, `send`, `call{value:}`) or token operations (`IERC20.transfer`, `safeTransfer`).
- There is no validation that the supplied address is not `address(0)`.

**Skip this skill if:** The contract already uses `require(_addr != address(0))` checks on all critical address setters, the contract inherits from OpenZeppelin's `Ownable2Step` (which validates internally), or the zero-address assignment is intentional (e.g., burn mechanics).

---

## 1. Meta-Data
- **Category:** Input Validation / Smart Contract Logic
- **Target Component:** Smart Contracts (Solidity), EVM-compatible chains
- **Complexity:** Low — requires static analysis of address setter functions and tracing their usage in fund flows
- **Estimated CVSS:** 7.2 (High) when critical fund recipients can be set to zero address, causing permanent fund loss (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H)
- **Reference:** CWE-20 (Improper Input Validation), Solidity documentation on address type defaults

---

## 2. Prerequisites (Trigger Conditions)
- [ ] The smart contract has a function that sets an `address` state variable used as a fund recipient.
- [ ] The setter function lacks a `require(addr != address(0))` check.
- [ ] The stored address is later used in fund-transferring operations (ETH transfers, ERC20 transfers, or delegate calls).
- [ ] The setter is callable by a user, admin, or constructor parameter — any path where the zero address can be supplied.
- [ ] There is no secondary validation or two-step confirmation pattern that would catch the zero address before funds are sent.

---

## 3. Reconnaissance & Detection

### 3.1 Locate Address Setter Functions

```bash
# Find functions that accept address parameters and assign them to state variables
grep -rn "function\s\+set\|function\s\+update\|function\s\+change" --include="*.sol" | grep "address"

# Find direct state variable assignments from address parameters
grep -rn "=\s*_\w*[Aa]ddress\|=\s*_\w*[Bb]eneficiary\|=\s*_\w*[Rr]ecipient\|=\s*_\w*[Oo]wner\|=\s*_\w*[Vv]ault\|=\s*_\w*[Tt]reasury\|=\s*_\w*[Cc]ollector" --include="*.sol"

# Find constructor parameters that set addresses
grep -rn "constructor" --include="*.sol" -A10 | grep "address"
```

### 3.2 Trace Fund Flow from Stored Addresses

```bash
# Find ETH transfers using stored address variables
grep -rn "\.transfer(\|\.send(\|\.call{value:" --include="*.sol"

# Find ERC20 transfers to stored addresses
grep -rn "\.transfer(\|\.safeTransfer(\|\.transferFrom(" --include="*.sol"

# Cross-reference: find where beneficiary/recipient variables are used in transfers
grep -rn "beneficiary\|recipient\|feeCollector\|treasury\|vault\|owner" --include="*.sol" | grep -E "transfer|send|call"
```

### 3.3 Check for Existing Mitigations

```bash
# Look for zero-address checks
grep -rn "require.*!=\s*address(0)\|require.*!=\s*address(0x0)" --include="*.sol"

# Look for custom error patterns (Solidity 0.8.4+)
grep -rn "if.*==\s*address(0).*revert\|error\s*ZeroAddress\|error\s*InvalidAddress" --include="*.sol"

# Look for OpenZeppelin address validation or Ownable2Step
grep -rn "import.*Ownable2Step\|import.*Address\b" --include="*.sol"
```

### 3.4 Vulnerability Decision Table

| Pattern Found | Impact | Vulnerable? |
|---|---|---|
| Address setter with no `address(0)` check + address used in ETH/token transfer | Permanent fund loss to burn address | **YES — High** |
| Address setter with no check + address used only in access control (not transfers) | Lockout but no fund loss | **YES — Medium** (admin lockout) |
| Constructor sets address with no check + address is immutable | Permanent fund loss, no recovery path | **YES — Critical** (no remediation possible) |
| Address setter with `require(addr != address(0))` | Validated | **No** |
| Address setter behind `Ownable2Step` or two-step confirmation | Validated via acceptance step | **No** |
| Address setter where zero address is intentional (burn function) | Design choice | **No** — intended behavior |
| Address set via `Ownable.transferOwnership()` without override | Depends on OZ version — older versions lack the check | **Possible** — check OZ version |

---

## 4. Exploitation Chain (Step-by-Step)

### Step 1 — Identify the Vulnerable Setter
Read the contract and confirm a function assigns an address parameter to a state variable without validation.

```solidity
// VULNERABLE PATTERN — the target
address public beneficiary;

function setBeneficiary(address _beneficiary) external onlyOwner {
    beneficiary = _beneficiary; // No zero-address check
}
```

### Step 2 — Trace the Fund Dependency
Confirm that the stored address is used in a fund transfer operation.

```solidity
// Fund flow depends on the unchecked address
function withdrawFunds() external {
    uint256 balance = address(this).balance;
    payable(beneficiary).transfer(balance); // Sends to whatever beneficiary is set to
}
```

### Step 3 — Determine the Attack Surface
Evaluate who can call the setter and under what conditions.

```
Attack Surface Analysis:
├── Setter is public/external with no auth?
│   └── Any user can set beneficiary = address(0)  → CRITICAL
├── Setter has onlyOwner?
│   └── Admin error or compromised admin key → HIGH
├── Address set only in constructor?
│   └── Deployment error → HIGH (immutable, no recovery)
└── Setter has timelock/multisig?
    └── Reduced likelihood but still possible → MEDIUM
```

### Step 4 — Execute the Attack (or Demonstrate the Risk)
If the setter has no access control, the attacker directly calls it with `address(0)`:

```solidity
// Attacker calls:
vulnerableContract.setBeneficiary(address(0));
```

If the setter is admin-only, the risk materializes through:
- Social engineering of the admin
- Compromised admin private key
- Admin accidentally passing `address(0)` (e.g., missing parameter in a script)
- Uninitialized address variable in deployment script defaults to `address(0)`

### Step 5 — Confirm Fund Loss
Once the beneficiary is set to `address(0)` and a withdrawal is triggered, ETH or tokens are sent to the burn address. On EVM chains, `address(0)` is a valid destination — the transfer succeeds, and funds are irrecoverable.

```
Impact Timeline:
T=0  Contract holds 100 ETH. beneficiary = 0xLegitimate.
T=1  setBeneficiary(address(0)) is called (by attacker or admin error).
T=2  beneficiary = 0x0000000000000000000000000000000000000000.
T=3  withdrawFunds() is called. 100 ETH sent to address(0).
T=4  Funds are permanently lost. No on-chain recovery mechanism exists.
```

---

## 5. Code Evidence — Vulnerable vs Patched

### Vulnerable (No Zero-Address Validation)
```solidity
// VULNERABLE: Accepts any address including address(0)
address public beneficiary;
address public feeCollector;
IERC20 public rewardToken;

function setBeneficiary(address _beneficiary) external onlyOwner {
    beneficiary = _beneficiary;
}

function setFeeCollector(address _collector) external onlyOwner {
    feeCollector = _collector;
}

function setRewardToken(address _token) external onlyOwner {
    rewardToken = IERC20(_token);
}
```

### Patched (Option A — Explicit require Check)
```solidity
// SAFE: Validates address is not zero before assignment
function setBeneficiary(address _beneficiary) external onlyOwner {
    require(_beneficiary != address(0), "Invalid address: zero address");
    beneficiary = _beneficiary;
}

function setFeeCollector(address _collector) external onlyOwner {
    require(_collector != address(0), "Invalid address: zero address");
    feeCollector = _collector;
}

function setRewardToken(address _token) external onlyOwner {
    require(_token != address(0), "Invalid address: zero address");
    rewardToken = IERC20(_token);
}
```

### Patched (Option B — Custom Error with Solidity 0.8.4+)
```solidity
// SAFE: Gas-efficient custom error pattern
error ZeroAddress();

function setBeneficiary(address _beneficiary) external onlyOwner {
    if (_beneficiary == address(0)) revert ZeroAddress();
    beneficiary = _beneficiary;
}
```

### Patched (Option C — Two-Step Transfer Pattern)
```solidity
// SAFE: Requires the new address to actively accept the role
address public beneficiary;
address public pendingBeneficiary;

function proposeBeneficiary(address _newBeneficiary) external onlyOwner {
    require(_newBeneficiary != address(0), "Invalid address: zero address");
    pendingBeneficiary = _newBeneficiary;
}

function acceptBeneficiary() external {
    require(msg.sender == pendingBeneficiary, "Not pending beneficiary");
    beneficiary = pendingBeneficiary;
    pendingBeneficiary = address(0);
}
```

### Patched (Option D — Internal Validation Helper)
```solidity
// SAFE: Reusable modifier for multiple setters
modifier notZeroAddress(address _addr) {
    require(_addr != address(0), "Invalid address: zero address");
    _;
}

function setBeneficiary(address _beneficiary) external onlyOwner notZeroAddress(_beneficiary) {
    beneficiary = _beneficiary;
}

function setFeeCollector(address _collector) external onlyOwner notZeroAddress(_collector) {
    feeCollector = _collector;
}
```

---

## 6. PoC Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @notice Minimal vulnerable contract demonstrating missing zero-address validation
contract VulnerableVault {
    address public beneficiary;
    address public owner;

    constructor(address _beneficiary) payable {
        owner = msg.sender;
        beneficiary = _beneficiary; // No zero-address check in constructor either
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function setBeneficiary(address _beneficiary) external onlyOwner {
        // VULNERABLE: No zero-address validation
        beneficiary = _beneficiary;
    }

    function withdrawToBeneficiary() external {
        uint256 balance = address(this).balance;
        require(balance > 0, "No funds");
        (bool success, ) = payable(beneficiary).call{value: balance}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}

/// @notice Fixed contract with proper validation
contract FixedVault {
    address public beneficiary;
    address public owner;

    error ZeroAddress();

    constructor(address _beneficiary) payable {
        if (_beneficiary == address(0)) revert ZeroAddress();
        owner = msg.sender;
        beneficiary = _beneficiary;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function setBeneficiary(address _beneficiary) external onlyOwner {
        if (_beneficiary == address(0)) revert ZeroAddress();
        beneficiary = _beneficiary;
    }

    function withdrawToBeneficiary() external {
        uint256 balance = address(this).balance;
        require(balance > 0, "No funds");
        (bool success, ) = payable(beneficiary).call{value: balance}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}

contract ZeroAddressValidationTest is Test {
    VulnerableVault vulnerable;
    FixedVault fixed_;

    address constant LEGITIMATE_BENEFICIARY = address(0xBEEF);
    uint256 constant VAULT_BALANCE = 10 ether;

    function setUp() public {
        // Deploy vulnerable vault with legitimate beneficiary and fund it
        vulnerable = new VulnerableVault{value: VAULT_BALANCE}(LEGITIMATE_BENEFICIARY);

        // Deploy fixed vault
        fixed_ = new FixedVault{value: VAULT_BALANCE}(LEGITIMATE_BENEFICIARY);
    }

    /// @notice Demonstrates that the vulnerable contract allows setting beneficiary to address(0)
    function test_vulnerableAllowsZeroAddress() public {
        // Verify initial state
        assertEq(vulnerable.beneficiary(), LEGITIMATE_BENEFICIARY);
        assertEq(address(vulnerable).balance, VAULT_BALANCE);

        // Owner sets beneficiary to zero address (simulating admin error or attack)
        vulnerable.setBeneficiary(address(0));
        assertEq(vulnerable.beneficiary(), address(0));

        // Record balance of address(0) before withdrawal
        uint256 burnBalanceBefore = address(0).balance;

        // Withdraw sends funds to address(0) — permanent loss
        vulnerable.withdrawToBeneficiary();

        // Verify funds are gone from the vault
        assertEq(address(vulnerable).balance, 0);

        // Verify funds went to address(0) — irrecoverable
        assertEq(address(0).balance, burnBalanceBefore + VAULT_BALANCE);

        emit log(">>> [VULNERABLE] Funds sent to address(0) — permanently lost");
        emit log_named_uint("ETH lost to burn address (wei)", VAULT_BALANCE);
    }

    /// @notice Demonstrates that the vulnerable constructor accepts address(0)
    function test_vulnerableConstructorAcceptsZero() public {
        // Deploy with address(0) as beneficiary — simulating deployment script error
        VulnerableVault badDeploy = new VulnerableVault{value: 5 ether}(address(0));

        assertEq(badDeploy.beneficiary(), address(0));

        uint256 burnBalanceBefore = address(0).balance;
        badDeploy.withdrawToBeneficiary();

        assertEq(address(0).balance, burnBalanceBefore + 5 ether);
        emit log(">>> [VULNERABLE] Constructor accepted address(0) — funds lost at first withdrawal");
    }

    /// @notice Demonstrates that the fixed contract rejects address(0) in the setter
    function test_fixedRejectsZeroAddress() public {
        vm.expectRevert(FixedVault.ZeroAddress.selector);
        fixed_.setBeneficiary(address(0));

        // Beneficiary remains unchanged
        assertEq(fixed_.beneficiary(), LEGITIMATE_BENEFICIARY);
        emit log(">>> [SAFE] setBeneficiary(address(0)) correctly reverted");
    }

    /// @notice Demonstrates that the fixed constructor rejects address(0)
    function test_fixedConstructorRejectsZero() public {
        vm.expectRevert(FixedVault.ZeroAddress.selector);
        new FixedVault{value: 5 ether}(address(0));

        emit log(">>> [SAFE] Constructor with address(0) correctly reverted");
    }

    /// @notice Demonstrates the ERC20 variant — token loss to zero address
    function test_vulnerableTokenTransferToZero() public {
        // This test documents the pattern — in practice, most ERC20 implementations
        // block transfer to address(0), but the contract should not rely on the token
        // implementation for this check.
        emit log(">>> ERC20 variant: If token.transfer(address(0), amount) succeeds,");
        emit log("    tokens are permanently burned. Contract must validate before calling.");
    }
}
```

**Run the PoC:**
```bash
# Using Foundry
forge test --match-contract ZeroAddressValidationTest -vvv

# Expected output:
# [PASS] test_vulnerableAllowsZeroAddress()          — Demonstrates fund loss
# [PASS] test_vulnerableConstructorAcceptsZero()      — Demonstrates constructor risk
# [PASS] test_fixedRejectsZeroAddress()               — Demonstrates the fix works
# [PASS] test_fixedConstructorRejectsZero()           — Demonstrates constructor fix
# [PASS] test_vulnerableTokenTransferToZero()         — Documents ERC20 variant
```

---

## 7. Report Template

### Title
`[High] Missing Zero-Address Validation in <function_name>() Enables Irreversible Fund Loss`

### Summary
The `<function_name>()` function in `<file_path>` accepts an `address` parameter and assigns it to the `<state_variable>` state variable without validating that the address is not `address(0)`. This variable is subsequently used as the destination for fund transfers in `<transfer_function>()`. An attacker (or an admin error) can set this variable to `address(0)`, causing all subsequent fund transfers to be sent to the burn address, resulting in permanent and irrecoverable fund loss.

### Impact
- **Irreversible fund loss:** All ETH or tokens sent to `address(0)` are permanently unrecoverable on EVM chains.
- **No on-chain remediation:** Once funds are transferred to the zero address, no transaction can recover them.
- **Attack cost:** Zero (beyond gas fees) — the attacker only needs to call the setter function.
- **Scope:** All funds flowing through the affected transfer function are at risk.

### Severity
**High** — CVSS 7.2 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H)

Escalates to **Critical** (CVSS 9.1) if:
- The setter has no access control (any user can call it), OR
- The address is set in the constructor with no validation and is immutable.

### Steps to Reproduce
1. Deploy the contract on a local fork or testnet.
2. Call `<function_name>(address(0))` to set the recipient to the zero address.
3. Trigger the fund transfer function `<transfer_function>()`.
4. Observe that funds are sent to `0x0000000000000000000000000000000000000000`.
5. Verify the funds are irrecoverable — no function exists to retrieve them from `address(0)`.

### Recommended Fix
1. **Minimum:** Add `require(_addr != address(0), "Invalid address")` to every function that sets a critical address.
2. **Better:** Use Solidity 0.8.4+ custom errors (`if (_addr == address(0)) revert ZeroAddress()`) for gas efficiency.
3. **Best:** Implement a two-step transfer pattern where the new address must call an `accept()` function, preventing both zero-address and typo errors.
4. **Also validate:** Constructor parameters, `initialize()` functions in proxy patterns, and any function that accepts a token contract address.

---

## 8. References
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [Solidity Docs — Address Type](https://docs.soliditylang.org/en/latest/types.html#address)
- [OpenZeppelin Ownable2Step — Two-Step Ownership Transfer](https://docs.openzeppelin.com/contracts/4.x/api/access#Ownable2Step)
- [ConsenSys Smart Contract Best Practices — General Philosophy](https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/)
- [Slither Detector — Missing Zero-Address Validation](https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation)
- [OpenZeppelin Address Utility](https://docs.openzeppelin.com/contracts/4.x/api/utils#Address)
