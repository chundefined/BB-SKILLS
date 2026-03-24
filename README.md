# BB-SKILLS

A structured skill tree for bug bounty hunting. Each skill is derived from real bug bounty reports — the logic is extracted and codified into a step-by-step methodology that Claude can navigate and execute during security audits.

---

## How It Works

Claude navigates the tree by reading `INDEX.md` files to route, then loads a `SKILL.md` only when the applicable vulnerability is confirmed.

```
INDEX.md   →   navigation only (signals → next path)
SKILL.md   →   full execution guide (recon, exploit chain, PoC, report)
```

**Navigation flow example** — auditing a Solidity smart contract:

```
bb-skills/INDEX.md              "blockchain signals" → web3/
bb-skills/web3/INDEX.md         "Solidity signals"  → smart-contracts/
bb-skills/web3/smart-contracts/INDEX.md   "loop + push()" → dos-unbounded-gas-loop/SKILL.md
bb-skills/web3/smart-contracts/dos-unbounded-gas-loop/SKILL.md   ← execute
```

---

## Project Structure

```
bb-skills/
├── INDEX.md                          ← Start here. Routes by domain.
├── web2/
│   ├── INDEX.md                      ← Routes by vulnerability class
│   └── broken-access-control/
│       ├── INDEX.md                  ← Lists skills + quick recon commands
│       └── auth-bypass-header-stripping-file-overwrite/
│           └── SKILL.md             ← Full skill
└── web3/
    ├── INDEX.md                      ← Routes by subcategory
    ├── smart-contracts/
    │   ├── INDEX.md
    │   ├── dos-unbounded-gas-loop/
    │   │   └── SKILL.md
    │   └── zero-address-validation/
    │       └── SKILL.md
    ├── defi/
    │   ├── INDEX.md
    │   └── frontrunning-sandwich-attack/
    │       └── SKILL.md
    └── consensus/
        ├── INDEX.md
        └── bft-validator-threshold/
            └── SKILL.md
```

---

## Adding a New Skill

### 1. Create the skill file

```
bb-skills/<domain>/<subcategory>/<vuln-name>/SKILL.md
```

Use kebab-case for the folder name. Be specific: `missing-deadline-check` not `defi-bug`.

### 2. Register it in the subcategory INDEX.md

Add a row to the Skills table in `bb-skills/<domain>/<subcategory>/INDEX.md`:

```markdown
| Skill name | CWE | Trigger pattern | Severity | File |
| Your skill | CWE-XXX | The code pattern that indicates this vuln | High/Critical | `your-skill-name/SKILL.md` |
```

The **trigger pattern** is the most important field — it's what Claude uses to decide whether to load your skill.

### 3. If adding a new subcategory

Create the subcategory folder and its `INDEX.md`, then add a row to the domain `INDEX.md` (`web2/INDEX.md` or `web3/INDEX.md`):

```markdown
| subcategory-name | signal1, signal2, signal3 | `subcategory-name/INDEX.md` |
```

That's it. No other files need to change.

---

## SKILL.md Template

Every skill follows the same structure:

```
# Skill Title

## 0. When to Use
## 1. Meta-Data         (category, CWE, CVSS, severity)
## 2. Prerequisites     (conditions that must be true)
## 3. Recon & Detection (commands, decision table)
## 4. Exploitation Chain
## 5. Code Evidence     (vulnerable vs patched)
## 6. PoC
## 7. Evasion / Edge Cases
## 8. Report Template
## 9. References
```

---

## Current Skills

| Domain | Subcategory | Skill | Severity |
|---|---|---|---|
| Web2 | broken-access-control | Auth Bypass via Bearer Header Stripping + File Overwrite | High–Critical |
| Web3 | smart-contracts | DoS via Unbounded Gas Consumption in Loop | High–Critical |
| Web3 | smart-contracts | Missing Zero-Address Validation | High–Critical |
| Web3 | defi | Transaction Frontrunning & Sandwich Attack | High–Critical |
| Web3 | consensus | Insufficient BFT Validator Threshold for Finality | Critical |
