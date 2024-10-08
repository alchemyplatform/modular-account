// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

import {SignatureType} from "../../libraries/SignatureType.sol";
import {BaseModule} from "../BaseModule.sol";
import {ReplaySafeWrapper} from "../ReplaySafeWrapper.sol";

/// @title ECSDA Validation
/// @author ERC-6900 Authors
/// @notice This validation enables any ECDSA (secp256k1 curve) signature validation or Contract Owner signature
/// validation. It handles installation by each entity (entityId).
/// Note:
///    - Uninstallation will NOT disable all installed validation entities. Account must remove access for each
/// validation if want to disable all validations.
///    - None of the functions are installed on the account. Account states are to be retrieved from this global
/// singleton directly.
///    - This validation supports ERC-1271. The signature is valid if it is signed by the owner's private key.
///    - This validation supports composition that other validation can relay on entities in this validation
/// to validate partially or fully.
contract ECDSAValidationModule is IValidationModule, ReplaySafeWrapper, BaseModule {
    using MessageHashUtils for bytes32;

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    mapping(uint32 entityId => mapping(address account => address)) public signers;

    /// @notice This event is emitted when Signer of the account's validation changes.
    /// @param account The account whose validation Signer changed.
    /// @param entityId The entityId for the account and the signer.
    /// @param newSigner The address of the new signer.
    /// @param previousSigner The address of the previous signer.
    event SignerTransferred(
        address indexed account, uint32 indexed entityId, address indexed newSigner, address previousSigner
    ) anonymous;

    error InvalidSignatureType();
    error NotAuthorized();

    /// @notice Transfer Signer of the account's validation to `newSigner`.
    /// @param entityId The entityId for the account and the signer.
    /// @param newSigner The address of the new signer.
    function transferSigner(uint32 entityId, address newSigner) external {
        _transferSigner(entityId, newSigner);
    }

    /// @inheritdoc IModule
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, address newSigner) = abi.decode(data, (uint32, address));
        _transferSigner(entityId, newSigner);
    }

    /// @inheritdoc IModule
    function onUninstall(bytes calldata data) external override {
        uint32 entityId = abi.decode(data, (uint32));
        _transferSigner(entityId, address(0));
    }

    /// @inheritdoc IValidationModule
    function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        // Validate the user op signature against the owner.
        if (_checkSig(signers[entityId][userOp.sender], userOpHash.toEthSignedMessageHash(), userOp.signature)) {
            return _SIG_VALIDATION_PASSED;
        }
        return _SIG_VALIDATION_FAILED;
    }

    /// @inheritdoc IValidationModule
    function validateRuntime(
        address account,
        uint32 entityId,
        address sender,
        uint256,
        bytes calldata,
        bytes calldata
    ) external view override {
        // Validate that the sender is the owner of the account or self.
        if (sender != signers[entityId][account]) {
            revert NotAuthorized();
        }
        return;
    }

    /// @inheritdoc IValidationModule
    /// @dev The signature is valid if it is signed by the owner's private key
    /// (if the owner is an EOA) or if it is a valid ERC-1271 signature from the
    /// owner (if the owner is a contract).
    /// Note that the digest is wrapped in an EIP-712 struct to prevent cross-account replay attacks. The
    /// replay-safe hash may be retrieved by calling the public function `replaySafeHash`.
    function validateSignature(address account, uint32 entityId, address, bytes32 digest, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        bytes32 _replaySafeHash = replaySafeHash(account, digest);
        if (_checkSig(signers[entityId][account], _replaySafeHash, signature)) {
            return _1271_MAGIC_VALUE;
        }
        return _1271_INVALID;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Module interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "erc6900.ecdsa-validation-module.1.0.0";
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(BaseModule, IERC165)
        returns (bool)
    {
        return (interfaceId == type(IValidationModule).interfaceId || super.supportsInterface(interfaceId));
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function _transferSigner(uint32 entityId, address newSigner) internal {
        address previousSigner = signers[entityId][msg.sender];
        signers[entityId][msg.sender] = newSigner;
        emit SignerTransferred(msg.sender, entityId, newSigner, previousSigner);
    }

    function _checkSig(address owner, bytes32 digest, bytes calldata sig) internal view returns (bool) {
        if (sig.length < 1) {
            revert InvalidSignatureType();
        }
        SignatureType sigType = SignatureType(uint8(bytes1(sig)));
        if (sigType == SignatureType.EOA) {
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig[1:]);
            if (err == ECDSA.RecoverError.NoError && recovered == owner) {
                return true;
            }
            return false;
        } else if (sigType == SignatureType.CONTRACT_OWNER) {
            return SignatureChecker.isValidERC1271SignatureNow(owner, digest, sig[1:]);
        }
        revert InvalidSignatureType();
    }
}
