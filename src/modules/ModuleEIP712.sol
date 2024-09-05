// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

// A base for modules that use EIP-712 structured data signing.
//
// Unlike other EIP712 libraries, this mixin uses the salt field to hold the account address.
//
// It omits the name and version from the EIP-712 domain, as modules are intended to be deployed as
// immutable singletons, thus a different versions and instances would have a different module address.
//
// Due to depending on the account address to calculate the domain separator, this abstract contract does not
// implement EIP-5267, as the domain retrieval function does not provide a parameter to use for the account address
// (internally the verifyingContract), and the computed `msg.sender` for an `eth_call` without an override is
// address(0).
abstract contract ModuleEIP712 {
    // keccak256(
    //     "EIP712Domain(uint256 chainId,address verifyingContract,bytes32 salt)"
    // )
    bytes32 private constant _DOMAIN_SEPARATOR_TYPEHASH =
        0x71062c282d40422f744945d587dbf4ecfd4f9cfad1d35d62c944373009d96162;

    function _domainSeparator(address account) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                _DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(this), bytes32(uint256(uint160(account)))
            )
        );
    }
}
