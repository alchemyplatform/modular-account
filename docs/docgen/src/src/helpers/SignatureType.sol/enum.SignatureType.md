# SignatureType
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/a15fd11665cc3bcdef40d456208c0f7907b5a3eb/src/helpers/SignatureType.sol)

An enum that is prepended to signatures to differentiate between EOA and contract owner signatures.


```solidity
enum SignatureType {
    EOA,
    CONTRACT_OWNER
}
```

