// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

/// @title ERC-7739 Replay-Safe Wrapper Library
/// @notice A library for ERC-7739-compliant nested EIP-712 wrappers over EIP-1271 digests.
/// @dev This allows for efficient, readable ERC-1271 signature schemes for smart contract accounts.
/// The difference between a module hash and an account hash is:
/// - Account domains include only chainId and verifyingContract of itself (not the implementation).
/// - Module domains include chainId, verifyingContract of the module, and uses the optional salt param, using
///   the account address.
library ERC7739ReplaySafeWrapperLib {
    // Points to a location in memory with EIP-712 formatted `encodeType(TypedDataSign)`, excluding the first two
    // words for typeHash(TypedDataSign)` and `typeHash(contents)`. Does not store the length, because this has a
    // fixed size of `0x120` (9 words).
    type MemoryLocation is bytes32;

    /// @dev `keccak256("PersonalSign(bytes prefixed)")`.
    bytes32 internal constant _PERSONAL_SIGN_TYPEHASH =
        0x983e65e5148e570cd828ead231ee759a8d7958721a768f93bc4483ba005c32de;

    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract,bytes32 salt)")
    bytes32 internal constant _DOMAIN_SEPARATOR_TYPEHASH_MODULE =
        0x71062c282d40422f744945d587dbf4ecfd4f9cfad1d35d62c944373009d96162;

    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
    bytes32 internal constant _DOMAIN_SEPARATOR_TYPEHASH_ACCOUNT =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256("")
    bytes32 internal constant _HASH_EMPTY_BYTES =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

    /// @notice Helper function to obtain the ERC-7739 digest on an incoming EIP-712 digest
    /// @dev This should be used in accounts
    /// @param account The account address
    /// @param hash The incoming app digest. This should be generated via a EIP-712 process
    /// @param signature The full ERC-7739 signature
    /// @return bytes32 The ERC-7739 digest
    /// @return bytes The inner signature
    function validateERC7739SigFormatForAccount(address account, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bytes32, bytes calldata)
    {
        MemoryLocation t;
        (t, hash, signature) = _validateERC7739SigFormat(typedDataSignFieldsForAccount(account), hash, signature);
        if (isZero(t)) hash = hashTypedDataForAccount(account, hash); // `PersonalSign` workflow.
        return (hash, signature);
    }

    /// @notice Helper function to obtain and arrange the eip712 fields for an account
    /// @dev From
    /// github/erc7579/erc7739Validator/blob/f8cbd4b58a7226cce18e9b8bc380da51174daf53/src/ERC7739Validator.sol#L283
    /// which is based on
    /// github/Vectorized/solady/blob/351548a824d57c1c0fec688fdfe3a44a8e17efc3/src/accounts/ERC1271.sol#L253
    /// @param account The account address
    /// @return m The memory location of this struct
    function typedDataSignFieldsForAccount(address account) internal view returns (MemoryLocation m) {
        bytes1 fields = bytes1(hex"0C"); // 001100
        // !string memory name;
        // !string memory version;
        // uint256 chainId = chainId;
        // address verifyingContract = address(this);
        // !bytes32 salt;
        // !uint256[] memory extensions;
        assembly ("memory-safe") {
            m := mload(0x40) // Grab the free memory pointer.
            mstore(0x40, add(m, 0x120)) // Allocate the memory.
            // Skip 2 words for the `typedDataSignTypehash` and `contents` struct hash.
            mstore(add(m, 0x40), fields)
            mstore(add(m, 0x60), _HASH_EMPTY_BYTES)
            mstore(add(m, 0x80), _HASH_EMPTY_BYTES)
            mstore(add(m, 0xa0), chainid())
            mstore(add(m, 0xc0), account)
            mstore(add(m, 0xe0), 0)
            mstore(add(m, 0x100), _HASH_EMPTY_BYTES)
        }
    }

    /// @notice Helper function to build the full personal sign hash, for an account
    /// @dev From
    /// github/erc7579/erc7739Validator/blob/f8cbd4b58a7226cce18e9b8bc380da51174daf53/src/ERC7739Validator.sol#L312
    /// @param account The account address
    /// @param structHash the hashStruct of arguments provided for an EIP-712 struct
    /// @return digest The ERC-7739 digest
    function hashTypedDataForAccount(address account, bytes32 structHash) internal view returns (bytes32 digest) {
        // !string memory name;
        // !string memory version;
        // uint256 chainId = chainId;
        // address verifyingContract = address(this);
        // !bytes32 salt;
        // !uint256[] memory extensions;
        /// @solidity memory-safe-assembly
        assembly {
            //Rebuild domain separator out of 712 domain
            let m := mload(0x40) // Load the free memory pointer.
            mstore(m, _DOMAIN_SEPARATOR_TYPEHASH_ACCOUNT)
            mstore(add(m, 0x20), _HASH_EMPTY_BYTES) // Name hash.
            mstore(add(m, 0x40), _HASH_EMPTY_BYTES) // Version hash.
            mstore(add(m, 0x60), chainid())
            mstore(add(m, 0x80), account)
            digest := keccak256(m, 0xa0) //domain separator

            // Hash typed data
            mstore(m, 0x1901) // Store "\x19\x01".
            mstore(add(m, 0x20), digest) // Store the domain separator.
            mstore(add(m, 0x40), structHash) // Store the struct hash.
            digest := keccak256(add(m, 0x1e), 0x42)
        }
    }

    /// @notice Helper function to obtain the ERC-7739 digest on an incoming EIP-712 digest
    /// @dev This should be used in modules
    /// @param account The account address
    /// @param module The module address
    /// @param hash The incoming app digest. This should be generated via a EIP-712 process
    /// @param signature The full ERC-7739 signature
    /// @return bytes32 The ERC-7739 digest
    /// @return bytes The inner signature
    function validateERC7739SigFormatForModule(
        address account,
        address module,
        bytes32 hash,
        bytes calldata signature
    ) internal view returns (bytes32, bytes calldata) {
        MemoryLocation t;
        (t, hash, signature) =
            _validateERC7739SigFormat(typedDataSignFieldsForModule(account, module), hash, signature);
        if (isZero(t)) hash = hashTypedDataForModule(account, module, hash); // `PersonalSign` workflow.
        return (hash, signature);
    }

    /// @notice Helper function to obtain and arrange the eip712 fields for a module
    /// @dev From
    /// github/erc7579/erc7739Validator/blob/f8cbd4b58a7226cce18e9b8bc380da51174daf53/src/ERC7739Validator.sol#L283
    /// which is based on
    /// github/Vectorized/solady/blob/351548a824d57c1c0fec688fdfe3a44a8e17efc3/src/accounts/ERC1271.sol#L253
    /// @param account The account address
    /// @param module The module address
    /// @return m The memory location of this struct
    function typedDataSignFieldsForModule(address account, address module)
        internal
        view
        returns (MemoryLocation m)
    {
        bytes1 fields = bytes1(hex"0E"); // 001110
        // !string memory name;
        // !string memory version;
        // uint256 chainId = chainId;
        // address verifyingContract = module;
        // bytes32 salt = account;
        // !uint256[] memory extensions;
        /// @solidity memory-safe-assembly
        assembly {
            m := mload(0x40) // Grab the free memory pointer.
            mstore(0x40, add(m, 0x120)) // Allocate the memory.
            // Skip 2 words for the `typedDataSignTypehash` and `contents` struct hash.
            mstore(add(m, 0x40), fields)
            mstore(add(m, 0x60), _HASH_EMPTY_BYTES)
            mstore(add(m, 0x80), _HASH_EMPTY_BYTES)
            mstore(add(m, 0xa0), chainid())
            mstore(add(m, 0xc0), module)
            mstore(add(m, 0xe0), account)
            mstore(add(m, 0x100), _HASH_EMPTY_BYTES)
        }
    }

    /// @notice Helper function to build the full personal sign hash for a module
    /// @dev From
    /// github/erc7579/erc7739Validator/blob/f8cbd4b58a7226cce18e9b8bc380da51174daf53/src/ERC7739Validator.sol#L312
    /// @param account The account address
    /// @param module The module address
    /// @param structHash the hashStruct of arguments provided for an EIP-712 struct
    /// @return digest The ERC-7739 digest
    function hashTypedDataForModule(address account, address module, bytes32 structHash)
        internal
        view
        returns (bytes32 digest)
    {
        // !string memory name;
        // !string memory version;
        // uint256 chainId = chainId;
        // address verifyingContract = address(this);
        // bytes32 salt = account;
        // !uint256[] memory extensions;
        /// @solidity memory-safe-assembly
        assembly {
            //Rebuild domain separator out of 712 domain
            let m := mload(0x40) // Load the free memory pointer.
            mstore(m, _DOMAIN_SEPARATOR_TYPEHASH_MODULE)
            mstore(add(m, 0x20), _HASH_EMPTY_BYTES) // Name hash.
            mstore(add(m, 0x40), _HASH_EMPTY_BYTES) // Version hash.
            mstore(add(m, 0x60), chainid())
            mstore(add(m, 0x80), module)
            mstore(add(m, 0xa0), account)
            digest := keccak256(m, 0xa0) //domain separator

            // Hash typed data
            mstore(m, 0x1901) // Store "\x19\x01".
            mstore(add(m, 0x20), digest) // Store the domain separator.
            mstore(add(m, 0x40), structHash) // Store the struct hash.
            digest := keccak256(add(m, 0x1e), 0x42)
        }
    }

    function isZero(MemoryLocation t) internal pure returns (bool) {
        return MemoryLocation.unwrap(t) == bytes32(0);
    }

    /// @notice Helper function to validate ERC7739 compatible nested EIP712 structs to guard against signature
    /// replay
    /// @dev Parses out the inner signature from the full signature and returns it
    /// Implementation is lifted from
    /// github/Vectorized/solady/blob/351548a824d57c1c0fec688fdfe3a44a8e17efc3/src/accounts/ERC1271.sol#L191
    /// Also see:
    /// github/erc7579/erc7739Validator/blob/f8cbd4b58a7226cce18e9b8bc380da51174daf53/src/ERC7739Validator.sol#L22
    /// @param t The location of all the types
    /// @param hash The incoming app digest. This should be generated through an EIP-712 process
    /// @return MemoryLocation the location of all the types. 0 signifies that PersonalSign should be used
    /// @return bytes32 Replay-safe hash, computed by wrapping the input hash in an EIP-712 struct.
    /// @return bytes Inner signature to use for verification.
    function _validateERC7739SigFormat(MemoryLocation t, bytes32 hash, bytes calldata signature)
        private
        pure
        returns (MemoryLocation, bytes32, bytes calldata)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer since we overwrite it below.
            // `c` is `contentsType.length`, which is stored in the last 2 bytes of the signature.
            let c := shr(240, calldataload(add(signature.offset, sub(signature.length, 2))))
            for {} 1 {} {
                let l := add(0x42, c) // Total length of appended data (32 + 32 + c + 2).
                let o := add(signature.offset, sub(signature.length, l)) // Offset of appended data.
                mstore(0x00, 0x1901) // Store the "\x19\x01" prefix.
                calldatacopy(0x20, o, 0x40) // Copy the `APP_DOMAIN_SEPARATOR` and `contents` struct hash.

                // Check the reconstructed hash doesn't match or if the appended data is invalid, i.e.
                // `appendedData.length > signature.length || contentsType.length == 0`. If so, we use
                // the `PersonalSign` workflow.
                if or(xor(keccak256(0x1e, 0x42), hash), or(lt(signature.length, l), iszero(c))) {
                    t := 0 // Set `t` to 0, denoting that we need to `hash = _hashTypedData(hash)`.
                    mstore(t, _PERSONAL_SIGN_TYPEHASH)
                    mstore(0x20, hash) // Store the `prefixed`.
                    hash := keccak256(t, 0x40) // Compute the `PersonalSign` struct hash.
                    break
                }

                // Else, use the `TypedDataSign` workflow. Here, we build the full 7739 type which has form
                // `TypedDataSign({ContentsName} contents,bytes1 fields,...){ContentsType}`.
                // E.g. for Permit(uint256 nonce,address spender,uint256 expiry,bool allowed), "Permit" is
                // the ContentsName and the full string is the ContentsType.
                mstore(m, "TypedDataSign(") // Store the start of `TypedDataSign`'s type encoding.
                let p := add(m, 0x0e) // Advance 14 bytes to skip "TypedDataSign(".
                calldatacopy(p, add(o, 0x40), c) // Copy `contentsType` to extract `contentsName`.
                // `d & 1 == 1` means that `contentsName` is invalid.
                let d := shr(byte(0, mload(p)), 0x7fffffe000000000000010000000000) // Starts with `[a-z(]`.
                // Store the end sentinel '(', and advance `p` until we encounter a '(' byte.
                for { mstore(add(p, c), 40) } iszero(eq(byte(0, mload(p)), 40)) { p := add(p, 1) } {
                    d := or(shr(byte(0, mload(p)), 0x120100000001), d) // Has a byte in ", )\x00".
                }
                mstore(p, " contents,bytes1 fields,string n") // Store the rest of the encoding.
                mstore(add(p, 0x20), "ame,string version,uint256 chain")
                mstore(add(p, 0x40), "Id,address verifyingContract,byt")
                mstore(add(p, 0x60), "es32 salt,uint256[] extensions)")
                p := add(p, 0x7f)
                calldatacopy(p, add(o, 0x40), c) // Copy `contentsType`.

                // We then build and hash the ERC-7739 digest
                // Fill in the missing fields of the `TypedDataSign`.
                calldatacopy(t, o, 0x40) // Copy the `contents` struct hash to `add(t, 0x20)`.
                mstore(t, keccak256(m, sub(add(p, c), m))) // Store `typedDataSignTypehash`.
                // The "\x19\x01" prefix is already at 0x00.
                // `APP_DOMAIN_SEPARATOR` is already at 0x20.
                mstore(0x40, keccak256(t, 0x120)) // `hashStruct(typedDataSign)`.
                // Compute the final hash, corrupted if `contentsName` is invalid.
                hash := keccak256(0x1e, add(0x42, and(1, d)))
                signature.length := sub(signature.length, l) // Truncate the signature.
                break
            }
            mstore(0x40, m) // Restore the free memory pointer.
        }
        return (t, hash, signature);
    }
}
