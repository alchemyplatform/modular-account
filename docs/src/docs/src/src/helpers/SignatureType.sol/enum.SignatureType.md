# SignatureType
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/30301ded6ae1a71c760933b7a75d6ac5437c1ae3/src/helpers/SignatureType.sol)

An enum that is prepended to signatures to differentiate between EOA and contract owner signatures.


```solidity
enum SignatureType {
    EOA,
    CONTRACT_OWNER
}
```

