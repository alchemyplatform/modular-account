# Features Overview

## Features
Modular Account v2 can:
1. Deploy contracts via `CREATE` or `CREATE2`.
2. Receive `ERC721` and `ERC1155` tokens.
3. Use applications that depend on `ERC1271` contract signatures.
4. Use applications that use the `ERC165` introspection standard.
5. Be upgradeable to or from most other smart contract account implementations. 
6. Be customized in many ways. All customization options can be found [here](./2-customizing-your-modular-account.md).

### ERC1271 Contract Signatures Support

Certain applications such as Permit2 or Cowswap use the ERC1271 contract signatures standard to determine if a smart contract has approved a certain action. Modular Account v2 implements to allow smart accounts to use these applications.

### Upgradeability

When modular accounts are created from the factory, an `ERC1967` proxy contract is deployed. Users can update the implementation their proxy points to to choose which smart account implementations to use. Modular Account v2 adheres to the `ERC7201` namespaced storage standard to prevent storage collisions when updating between different implementations.