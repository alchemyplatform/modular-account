# Modular Account

[![gh_ci_badge]][gh_ci_link]
[![tg_badge]][tg_link]

[gh_ci_badge]: https://github.com/alchemyplatform/modular-account/actions/workflows/test.yml/badge.svg
[gh_ci_link]: https://github.com/alchemyplatform/modular-account/actions/workflows/test.yml
[tg_badge]: https://img.shields.io/endpoint?color=neon&logo=telegram&label=chat&url=https://mogyo.ro/quart-apis/tgmembercount?chat_id=modular_account_standards
[tg_link]: https://t.me/modular_account_standards

![](./img/ma.png)

Alchemy's Modular Account is a maximally modular, upgradeable smart contract account that is compatible with [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) and [ERC-6900](https://eips.ethereum.org/EIPS/eip-6900).

> [!WARNING]  
> **This branch contains changes that are under development.** To use the latest audited version make sure to use the correct commit. The tagged versions can be found in the [releases](https://github.com/alchemyplatform/modular-account/releases).

## Overview

This repository contains:

- ERC-6900 compatible account implementations: [src/account](src/account)
- Account factory: [src/factory](src/factory)
- Helper contracts and libraries: [src/helpers](src/helpers), [src/libraries](src/libraries)
- ERC-6900 compatible modules: [src/modules](src/modules)
  - Validation modules:
    - [SingleSignerValidationModule](src/modules/validation/SingleSignerValidationModule.sol): Enables validation for a single signer (EOA or contract).
    - [WebAuthnValidationModule](src/modules/validation/WebAuthnValidationModule.sol): Enables validation for passkey signers.
  - Permission-enforcing hook modules:
    - [AllowlistModule](src/modules/permissions/AllowlistModule.sol): Enforces ERC-20 spend limits and address/selector allowlists.
    - [NativeTokenLimitModule](src/modules/permissions/NativeTokenLimitModule.sol): Enforces native token spend limits.
    - [PaymasterGuardModule](src/modules/permissions/PaymasterGuardModule.sol): Enforces use of a specific paymaster.
    - [TimeRangeModule](src/modules/permissions/TimeRangeModule.sol): Enforces time ranges for a given entity.

The contracts conform to these ERC versions:

- ERC-4337: [v0.7.0](https://github.com/eth-infinitism/account-abstraction/blob/releases/v0.7/erc/ERCS/erc-4337.md)
- ERC-6900: [v0.8.0-rc.5](https://github.com/erc6900/reference-implementation/blob/v0.8.0-rc.5/standard/ERCs/erc-6900.md)

## Development

### Building and testing

```bash
# Install dependencies
forge install
pnpm install

# Build
forge build
FOUNDRY_PROFILE=optimized-build forge build --sizes

# Lint
pnpm lint

# Format
pnpm fmt

# Coverage
pnpm lcov

# Generate gas snapshots
pnpm gas

# Test
pnpm test
forge test -vvv
```

### Deployment

A deployment script can be found in the `scripts/` folder

```bash
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

## Security and audits

Our audit reports can be found in [audits](/audits). The filenames for the reports have the format: `YYYY-MM-DD_VENDOR_FFFFFFF.pdf`, where `YYYY-MM-DD` refers to the date on which the final report was received, `VENDOR` refers to the conductor of the audit, and `FFFFFFF` refers to the short commit hash on which the audit was conducted.

### Bug bounty

Details of our bug bounty program can be found at https://hackerone.com/alchemyplatform.

### Acknowledgements

The contracts in this repository adhere to the ERC-6900 specification, and are heavily influenced by the design of the ERC-6900 reference implementation.

## License

The contracts provided in this repository in [src](src) are licensed under the GNU General Public License v3.0, included in our repository in [LICENSE-GPL](LICENSE-GPL).

Alchemy Insights, Inc., 548 Market St., PMB 49099, San Francisco, CA 94104; legal@alchemy.com
