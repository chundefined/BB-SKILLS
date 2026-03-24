# BB-SKILLS — Bug Bounty Skill Navigator

> **Rule:** Read INDEX.md files to route. Read SKILL.md only when you've confirmed the applicable vulnerability. Never skip levels — navigate domain → subcategory → skill.

## Domain Router

| Signals observed in target | Domain | Next file |
|---|---|---|
| blockchain, Solidity, `.sol`, EVM, DeFi, AMM, DEX, swap, validator, consensus, smart contract, Web3, on-chain | Web3 | `web3/INDEX.md` |
| web app, REST API, GraphQL, JWT, Bearer, file upload, HTTP headers, admin panel, IDOR, session, cookie | Web2 | `web2/INDEX.md` |

## Tree

```
bb-skills/
├── web2/
│   └── broken-access-control/
│       └── auth-bypass-header-stripping-file-overwrite/SKILL.md
└── web3/
    ├── smart-contracts/
    │   ├── dos-unbounded-gas-loop/SKILL.md
    │   └── zero-address-validation/SKILL.md
    ├── defi/
    │   └── frontrunning-sandwich-attack/SKILL.md
    └── consensus/
        └── bft-validator-threshold/SKILL.md
```

## Adding a New Skill
1. Create `<domain>/<subcategory>/<vuln-name>/SKILL.md`
2. Add a row to the subcategory `INDEX.md`
3. If new subcategory: add a row to the domain `INDEX.md`
