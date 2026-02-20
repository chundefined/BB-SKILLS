# Skill: BFT Consensus — Insufficient Validator Threshold for Finality

## 0. When to Use This Skill
Use this skill when **all** of the following are true:
- Target is a blockchain or DLT network using BFT-based consensus (QBFT, IBFT, Tendermint, HotStuff, or any fork).
- You have access to the consensus engine source code (Go, Rust, Java).
- You are looking for finality violations, double-spend vectors, or fork safety bugs.

**Skip this skill if:** The consensus is PoW, pure PoS without BFT finality, or you have no source access.

---

## 1. Meta-Data
- **Category:** Business Logic Flaw / Consensus Safety Violation
- **Target Component:** Blockchain Consensus Engine (QBFT, IBFT, Besu forks, Hyperledger)
- **Complexity:** High — requires static code analysis + cryptography/consensus knowledge
- **Estimated CVSS:** 9.0–9.8 (Critical) when exploitable on mainnet
- **Reference:** Castro & Liskov, *Practical Byzantine Fault Tolerance* (1999)

---

## 2. Prerequisites (Trigger Conditions)
- [ ] Target network uses BFT-based consensus: QBFT, IBFT, Tendermint, HotStuff, or derivative.
- [ ] Source code of the consensus engine is accessible (open source, GitHub, or decompilable binary).
- [ ] Network has a validator set (permissioned or semi-permissioned).

---

## 3. Reconnaissance & Detection

### 3.1 Locate the Consensus Engine Files

```bash
# Go projects (Besu forks, go-ethereum, Quorum)
find . -type f -name "*.go" | xargs grep -l "validators.F()\|QuorumSize\|ValidatorSet\|verifyCommittedSeals" 2>/dev/null
# Common paths in Besu/IBFT forks:
# consensus/istanbul/engine/engine.go
# consensus/qbft/validator/validator.go

# Rust projects (Substrate, custom chains)
find . -type f -name "*.rs" | xargs grep -l "quorum\|threshold\|validator_set" 2>/dev/null

# Java projects (Hyperledger Besu)
find . -type f -name "*.java" | xargs grep -l "quorum\|validatorSet\|threshold" 2>/dev/null
```

### 3.2 Find the Fault Tolerance and Quorum Functions

```bash
# Find F() calculation
grep -rn "func.*F()\|fn fault_tolerance\|getFaultTolerance\|byzantineFault" --include="*.go" --include="*.rs"

# Find the committed seals verification (the critical function)
grep -rn "verifyCommittedSeals\|checkCommits\|validateCommit\|validSeal" --include="*.go" --include="*.rs"

# Look for the comparison operator — this is where the bug lives
grep -rn "validSeal\s*<=\s*\|validSeal\s*<\s*\|commits\s*<=\s*F\|commits\s*<\s*quorum" --include="*.go"
```

### 3.3 Vulnerability Decision Table

| Code Pattern Found | Mathematical Meaning | Vulnerable? |
|---|---|---|
| `validSeal <= validators.F()` | Requires only F+1 signatures (~1/3 of N) | ✅ **YES — Critical** |
| `validSeal < validators.F()` | Requires F signatures (even worse) | ✅ **YES — Critical** |
| `validSeal < 2*F+1` | Requires 2F signatures (one short) | ⚠️ Borderline |
| `validSeal <= 2*F` | Requires 2F+1 — correct | ❌ Not vulnerable |
| `validSeal < quorum` where `quorum = 2F+1` | Correct | ❌ Not vulnerable |
| `len(commits)*3 <= len(validators)*2` | ceil(2N/3) check — correct | ❌ Not vulnerable |

---

## 4. Exploitation Chain (Step-by-Step)

### Step 1 — Confirm the Logic Flaw
Read the `verifyCommittedSeals` (or equivalent) function. Confirm the comparison uses `<= F()` instead of `< 2F+1`.

```go
// VULNERABLE CODE — the bug
validSeal := 0
committers, err := e.Signers(header)
for _, committer := range committers {
    if validators.GetByAddress(committer) != nil {
        validSeal++
    }
}
// BUG: Should be `validSeal < 2*validators.F()+1`
if validSeal <= validators.F() {
    return istanbulcommon.ErrInvalidCommittedSeals
}
```

### Step 2 — Calculate the Mathematical Impact

```python
def calculate_impact(n_validators: int) -> dict:
    """
    Given N validators, compute the attack parameters.
    """
    F = (n_validators - 1) // 3          # Max Byzantine faults tolerated
    threshold_buggy  = F + 1             # Signatures required by vulnerable code
    threshold_secure = 2 * F + 1         # Signatures required by correct BFT
    nodes_to_attack  = F + 1             # Nodes attacker must control
    
    return {
        "total_validators":         n_validators,
        "F (fault tolerance)":      F,
        "sigs_required_buggy_code": threshold_buggy,
        "sigs_required_correct":    threshold_secure,
        "nodes_attacker_needs":     nodes_to_attack,
        "pct_network_to_attack":    f"{(nodes_to_attack / n_validators) * 100:.1f}%",
        "savings_vs_honest_51pct":  f"Attacker needs {nodes_to_attack} nodes instead of {n_validators // 2 + 1}"
    }

# Example outputs:
# N=4  → F=1, bug needs 2 sigs, correct needs 3, attack with 2 nodes (50%)
# N=7  → F=2, bug needs 3 sigs, correct needs 5, attack with 3 nodes (42.9%)
# N=9  → F=2, bug needs 3 sigs, correct needs 7, attack with 3 nodes (33.3%) ← Most impactful
# N=13 → F=4, bug needs 5 sigs, correct needs 9, attack with 5 nodes (38.5%)
```

### Step 3 — Model the Attack Scenario (Testnet PoC)

```
Setup: N=9 validators. Attacker controls 3 nodes (F+1).

Timeline:
T=0  Honest nodes propose Block B (legitimate transaction).
T=1  Attacker's 3 nodes sign an alternative Block A (double-spend tx).
T=2  Block A gets finalized: validSeal=3, F=2, check is 3 <= 2 → FALSE → passes ✓
T=3  Block B also gets finalized by honest nodes with 7 signatures.
T=4  Two conflicting "finalized" blocks exist → FORK / SAFETY VIOLATION.
T=5  Attacker submits Block A's tx to exchange → exchange credits funds.
T=6  Honest chain on Block B → original funds still present → double-spend complete.
```

### Step 4 — Impact Escalation
- **Double-spend:** Attacker deposits funds on exchange using the fork, withdraws, and the canonical chain never recorded the deposit.
- **Permanent fork:** Two irreconcilable chain states, requiring manual intervention / chain halt.
- **Economic damage:** Exchange losses, chain credibility destroyed, potential legal exposure for the project.

---

## 5. Code Evidence — Vulnerable vs Patched

### Vulnerable
```go
// consensus/istanbul/engine/engine.go
if validSeal <= validators.F() {
    return istanbulcommon.ErrInvalidCommittedSeals
}
```

### Patched (Option A — Explicit 2F+1)
```go
// Require strictly more than 2F signatures = at least 2F+1
if validSeal < 2*validators.F()+1 {
    return istanbulcommon.ErrInvalidCommittedSeals
}
```

### Patched (Option B — Ceiling division, more robust)
```go
// ceil(2N/3) — handles edge cases with small N
quorum := int(math.Ceil(float64(2*validators.Size()) / 3.0))
if validSeal < quorum {
    return istanbulcommon.ErrInvalidCommittedSeals
}
```

---

## 6. PoC Template

```go
// File: consensus_threshold_test.go
// Purpose: Demonstrate that F+1 nodes can finalize a conflicting block
// Environment: Local devnet with N validators, attacker controls F+1

package consensus_test

import (
    "testing"
    "math"
)

func TestInsufficientThreshold(t *testing.T) {
    N := 9
    F := (N - 1) / 3  // F = 2
    
    // Simulate buggy check
    attackerNodes := F + 1  // 3 nodes
    buggyCheck    := attackerNodes <= F  // 3 <= 2 → false → PASSES (vulnerability)
    
    if !buggyCheck {
        t.Logf("[VULNERABLE] Attacker with %d/%d nodes can finalize block. F=%d, check: %d <= %d = false",
            attackerNodes, N, F, attackerNodes, F)
        // In real PoC: submit conflicting signed block to node RPC
    }
    
    // Correct check
    quorum := int(math.Ceil(float64(2*N) / 3.0))
    correctCheck := attackerNodes < quorum  // 3 < 7 → true → BLOCKED
    if correctCheck {
        t.Logf("[PATCHED]    Correct quorum=%d blocks attack from %d nodes", quorum, attackerNodes)
    }
}
```

---

## 7. Report Template

### Title
`[Critical] BFT Consensus: Insufficient Validator Threshold Allows Finality Violation and Double-Spend`

### Summary
The `verifyCommittedSeals` function in `<file path>` uses an incorrect threshold of `F+1` signatures to finalize blocks, instead of the mathematically required `2F+1`. This allows an attacker controlling only `~33%` of validators to produce a conflicting finalized block, breaking BFT safety guarantees and enabling double-spend attacks.

### Impact
- **Finality violation:** Two conflicting blocks can both pass the finality check.
- **Double-spend:** An attacker with `F+1` validators can exploit this against exchanges or bridges.
- **Chain halt / fork:** Permanent irreconcilable state requiring manual chain recovery.

### Severity
**Critical** — CVSS 9.1 (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)

### Steps to Reproduce
1. Deploy local network with N=9 validators (3 controlled by attacker).
2. Propose conflicting block signed by attacker's 3 nodes.
3. Observe block passes `verifyCommittedSeals` with `validSeal=3, F=2` (3 <= 2 is false → no error).
4. Observe honest chain also finalizes a different block.
5. Two finalized conflicting blocks now exist.

### Recommended Fix
Replace `validSeal <= validators.F()` with `validSeal < 2*validators.F()+1`.

---

## 8. References
- Castro & Liskov — *Practical Byzantine Fault Tolerance*, OSDI 1999
- [Hyperledger Besu IBFT 2.0 Spec](https://besu.hyperledger.org/private-networks/concepts/poa)
- [QBFT EIP](https://eips.ethereum.org/EIPS/eip-650)
- Related: Tendermint safety proof — https://arxiv.org/abs/1807.04938