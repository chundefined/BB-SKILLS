# Smart Contracts — Skills

## Quick Recon
```bash
# Unbounded loops (DoS candidate)
grep -rn "for.*\.length" --include="*.sol"

# Array growth via public functions (DoS amplifier)
grep -rn "\.push(" --include="*.sol"

# Address setters (zero-address candidate)
grep -rn "function.*[Ss]et.*[Aa]ddress\|= _.*address\|address.*=" --include="*.sol"

# Fund transfer (impact amplifier)
grep -rn "\.transfer(\|\.send(\|\.call{value:" --include="*.sol"

# Payable functions (value at risk)
grep -rn "function.*payable" --include="*.sol"
```

## Skills

| Skill | CWE | Trigger pattern | Severity | File |
|---|---|---|---|---|
| DoS via Unbounded Gas Consumption in Loop | CWE-400 | `for` loop iterates over a dynamic array whose length is growable via a public `push()` call on a critical function path | High → Critical (fund lock) | `dos-unbounded-gas-loop/SKILL.md` |
| Missing Zero-Address Validation | CWE-20 | `address` state variable updated by a setter function with no `require(addr != address(0))` guard; variable used in fund transfers | High → Critical (if immutable / no recovery) | `zero-address-validation/SKILL.md` |
| Reentrancy *(coming soon)* | CWE-841 | External call before state update (`transfer` / `call` before balance decrement) | Critical | — |
| Access Control — Missing Auth *(coming soon)* | CWE-862 | `public`/`external` function that changes critical state with no `onlyOwner` / `onlyRole` modifier | High–Critical | — |
| Integer Overflow / Underflow *(coming soon)* | CWE-190 | Arithmetic on `uint` without SafeMath (Solidity < 0.8) or unchecked block | Medium–High | — |
| Oracle Manipulation *(coming soon)* | CWE-20 | Spot price from `getReserves()` used directly in a single transaction without TWAP | High–Critical | — |
