# Alchemy Modular Smart Contract Account (MSCA)

Contracts for an upgradeable modular smart contract account that is compatible with ERC-4337, along with a set of plugins.

## Development

### Naming convention

- `selector` is used for all function selectors.
- `validation` and `validationFunction` are used to replace `validator`.
- `associated` and `associatedFunction` are used to represents `validationFunction` and `hook`

## Build

```bash
forge build

# or use the lite profile to reduce compilation time
FOUNDRY_PROFILE=lite forge build
```

## Syntax check

```bash
pnpm lint:src && pnpm lint:test
```

## Test

```bash
forge test -vvv

# or use the lite profile to reduce compilation time
FOUNDRY_PROFILE=lite forge test -vvv
```

## Generate Inspections

```bash
bash utils/inspect.sh
```

## Static Analysis

```bash
slither .
```

## External Libraries

We use Solady's highly optimized [UUPSUpgradeable](https://github.com/Vectorized/solady/blob/a061f38f27cd7ae330a86d42d3f15b4e7237f064/src/utils/UUPSUpgradeable.sol) in our contracts

## Deployment

```bash
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast
```
