# SignatureType
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/2824291b17c11e6f41963e8c13505f2476b92ee6/src/helpers/SignatureType.sol)

An enum that is prepended to signatures to differentiate between EOA and contract owner signatures.


```solidity
enum SignatureType {
    EOA,
    CONTRACT_OWNER
}
```

