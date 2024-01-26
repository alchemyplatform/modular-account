# Modular Account

Alchemy's Modular Account is a maximally modular, upgradeable Smart Contract Account that is compatible with [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) and [ERC-6900](https://eips.ethereum.org/EIPS/eip-6900).

## Overview

This repository contains:

- [Modular Account implementation](src/account)
- [Modular Account factories](src/factory)
- 2 ERC-6900 compatible plugins:
  - [MultiOwnerPlugin](src/plugins/owner) is a plugin supporting 1+ ECDSA owners.
  - [SessionKeyPlugin](src/plugins/session) enables session keys with optional permissions such as time ranges, token spend limits, and gas spend limits.

The account and plugins conform to these ERC versions:

- ERC-4337: 0.6.0
- ERC-6900: 0.7.0

## Development

### Naming convention

- `selector` is used for all function selectors.
- `validation` and `validationFunction` are used to replace `validator`.
- `associated` and `associatedFunction` are used to represents `validationFunction` and `hook`

### Building and Testing

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

## Security and Audits

We have done 2 audits from Spearbit and Quantstamp and will upload the reports shortly.

## License

The Modular Account libraries (all code inside the [src/libraries](src/libraries) directory) are licensed under the MIT License, also included in our repository in [LICENSE-MIT](LICENSE-MIT).

The Modular Account interfaces and ERC-6900 interfaces (all code inside the [src/interfaces](src/interfaces) directory) are licensed under the CC0 1.0 Universal License.

All other code for Modular Account is licensed under the GNU General Public License v3.0, also included in our repository in [LICENSE-GPL](LICENSE-GPL).

Alchemy Insights, Inc., 548 Market St., PMB 49099, San Francisco, CA 94104; legal@alchemy.com
