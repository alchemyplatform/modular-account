# Modular Account

[![gh_ci_badge]][gh_ci_link]
[![tg_badge]][tg_link]

[gh_ci_badge]: https://github.com/alchemyplatform/modular-account/actions/workflows/test.yml/badge.svg
[gh_ci_link]: https://github.com/alchemyplatform/modular-account/actions/workflows/test.yml
[tg_badge]: https://img.shields.io/endpoint?color=neon&logo=telegram&label=chat&url=https://mogyo.ro/quart-apis/tgmembercount?chat_id=modular_account_standards
[tg_link]: https://t.me/modular_account_standards

![](./img/ma.png)

Alchemy's Modular Account is a maximally modular, upgradeable smart contract account that is compatible with [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) and [ERC-6900](https://eips.ethereum.org/EIPS/eip-6900).

## Overview

This repository contains:

- [Modular Account implementation](src/account)
- [Modular Account factory](src/factory)
- 2 ERC-6900 compatible plugins:
  - [MultiOwnerPlugin](src/plugins/owner) is a plugin supporting 1+ ECDSA or contract owners.
  - [SessionKeyPlugin](src/plugins/session) enables session keys with optional permissions such as time ranges, token spend limits, and gas spend limits.

The account and plugins conform to these ERC versions:

- ERC-4337: [0.6.0](https://github.com/eth-infinitism/account-abstraction/blob/releases/v0.6/eip/EIPS/eip-4337.md)
- ERC-6900: [0.7.0](https://github.com/erc6900/reference-implementation/blob/v0.7.x/standard/ERCs/erc-6900.md)

## Development

### Naming convention

- `selector` is used for all function selectors.
- `validation` and `validationFunction` are used to represent `validator`.
- `associated` and `associatedFunction` are used to represent `validationFunction` and `hook`.

### Building and testing

```bash
# Build options
forge build
FOUNDRY_PROFILE=lite forge build
FOUNDRY_PROFILE=optimized-build forge build --sizes

# Lint
pnpm lint

# Test Options
forge test -vvv
FOUNDRY_PROFILE=lite forge test -vvv
```

### Deployment

A deployment script can be found in the `scripts/` folder

```bash
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

## Security and audits

Our audit reports from Spearbit and Quantstamp can be found in [audits](/audits). Note that the reports may contain references to the term MSCA, which stands for modular smart contract account, as defined in the [terms for ERC-6900](https://eips.ethereum.org/EIPS/eip-6900#terms). This is synonymous with modular account.

### Bug bounty

Details of our bug bounty program can be found at https://hackerone.com/alchemyplatform.

## License

The Modular Account libraries (all code inside the [src/libraries](src/libraries) directory) are licensed under the MIT License, also included in our repository in [LICENSE-MIT](LICENSE-MIT).

The Modular Account interfaces and ERC-6900 interfaces (all code inside the [src/interfaces](src/interfaces) directory) are licensed under the CC0 1.0 Universal License.

All other code for Modular Account is licensed under the GNU General Public License v3.0, also included in our repository in [LICENSE-GPL](LICENSE-GPL).

Alchemy Insights, Inc., 548 Market St., PMB 49099, San Francisco, CA 94104; legal@alchemy.com
