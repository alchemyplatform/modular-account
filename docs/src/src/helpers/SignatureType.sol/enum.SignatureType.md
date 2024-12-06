# SignatureType
[Git Source](https://github.com/ssh://alchemyplatform/modular-account/blob/22a036bde57711d56f967db6e1ecc2ae54755e1a/src/helpers/SignatureType.sol)

An enum that is prepended to signatures to differentiate between EOA and contract owner signatures.


```solidity
enum SignatureType {
    EOA,
    CONTRACT_OWNER
}
```

