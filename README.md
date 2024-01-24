# Modular Account

Alchemy's Modular Account is a maximally modular smart contract account. It is compatible with [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337), upgradeable, and is in-line with [ERC-6900](https://eips.ethereum.org/EIPS/eip-6900).

## Overview

This repository contains:
* The [Modular Account](https://github.com/alchemyplatform/modular-account/src/account)
* [Factory contracts for the Modular Account](https://github.com/alchemyplatform/modular-account/src/factory)
* 3 Modular Account compatible plugins:
    * [MultiOwnerPlugin](https://github.com/alchemyplatform/modular-account/src/plugins/owner) is a plugin supporting 1+ ECDSA owners. 
    * [TokenReceiverPlugin](https://github.com/alchemyplatform/modular-account/src/plugins/TokenReceiverPlugin.sol) contains ERC721/ERC777/ERC1155 token receivers. 
    * [SessionKeyPlugin](https://github.com/alchemyplatform/modular-account/src/plugins/session) enables session keys with additonal optional restrictions such as time ranges, token spend limits, and gas spend limits. 

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
pnpm lint:src && pnpm lint:test

# Test Options
forge test -vvv
FOUNDRY_PROFILE=lite forge test -vvv
```

### Deployment

A deployment script can be found in the `scripts/` folder
```bash
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast
```

## Security and Audits

We have done 2 audits from Spearbit and Quantstamp and will upload the reports shortly.

## License

The Modular Account libraries (i.e., all code inside the [src/libraries](src/libraries) directory) are licensed under the MIT License, also included in our repository in [LICENSE-MIT](LICENSE-MIT).

The Modular Account and ERC-6900 interfaces (i.e., all code inside the [src/interfaces](src/interfaces) directory) are licensed under the CC0 1.0 Universal License, also included in our repository in [LICENSE-CC0](LICENSE-CC0).

All other code for Modular Account is licensed under the GNU General Public License v3.0, also included in our repository in [COPYING](COPYING).

Alchemy Insights, Inc., 548 Market St., PMB 49099, San Francisco, CA 94104; legal@alchemy.com
