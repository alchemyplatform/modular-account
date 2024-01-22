// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {BasePlugin} from "../BasePlugin.sol";
import {IMultiOwnerPlugin} from "./IMultiOwnerPlugin.sol";
import {UpgradeableModularAccount, UUPSUpgradeable} from "../../account/UpgradeableModularAccount.sol";

import {
    ManifestAssociatedFunction,
    ManifestAssociatedFunctionType,
    ManifestFunction,
    PluginManifest,
    PluginMetadata,
    SelectorPermission
} from "../../interfaces/IPlugin.sol";
import {IStandardExecutor} from "../../interfaces/IStandardExecutor.sol";
import {UserOperation} from "../../interfaces/erc4337/UserOperation.sol";

import {
    AssociatedLinkedListSet, AssociatedLinkedListSetLib
} from "../../libraries/AssociatedLinkedListSetLib.sol";
import {CastLib} from "../../libraries/CastLib.sol";
import {SetValue} from "../../libraries/LinkedListSetUtils.sol";

/// @title Multi Owner Plugin
/// @author Alchemy
/// @notice This plugin allows more than one EOA or smart contract to own a modular account.
/// All owners have equal root access to the account.
///
/// It supports [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) signature
/// validation for both validating the signature on user operations and in
/// exposing its own `isValidSignature` method. This only works when the owner of
/// modular account also support ERC-1271.
///
/// ERC-4337's bundler validation rules limit the types of contracts that can be
/// used as owners to validate user operation signatures. For example, the
/// contract's `isValidSignature` function may not use any forbidden opcodes
/// such as `TIMESTAMP` or `NUMBER`, and the contract may not be an ERC-1967
/// proxy as it accesses a constant implementation slot not associated with
/// the account, violating storage access rules. This also means that the
/// owner of a modular account may not be another modular account if you want to
/// send user operations through a bundler.
contract MultiOwnerPlugin is BasePlugin, IMultiOwnerPlugin, IERC1271 {
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;
    using ECDSA for bytes32;

    string internal constant _NAME = "Multi Owner Plugin";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "Alchemy";

    bytes32 private constant _TYPE_HASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
    );
    bytes32 private constant _HASHED_NAME = keccak256(bytes(_NAME));
    bytes32 private constant _HASHED_VERSION = keccak256(bytes(_VERSION));
    bytes32 private immutable _SALT = bytes32(bytes20(address(this)));

    // ERC-4337 specific value: signature validation passed
    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    // ERC-4337 specific value: signature validation failed
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_MAGIC_VALUE_FAILURE = 0xffffffff;

    // keccak256("ERC6900Message(bytes message)");
    bytes32 private constant ERC6900_TYPEHASH = 0xa856bbdae1f2c6e4aa17a75ad7cc5650f184ec4b549174dd7258c9701d663fc6;

    AssociatedLinkedListSet internal _owners;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IMultiOwnerPlugin
    /// @dev If an owner is present in both ownersToAdd and ownersToRemove, it will be added as owner.
    /// The owner array cannot have 0 or duplicated addresses.
    function updateOwners(address[] memory ownersToAdd, address[] memory ownersToRemove)
        public
        isInitialized(msg.sender)
    {
        _removeOwnersOrRevert(_owners, msg.sender, ownersToRemove);
        _addOwnersOrRevert(_owners, msg.sender, ownersToAdd);

        if (_owners.isEmpty(msg.sender)) {
            revert EmptyOwnersNotAllowed();
        }

        emit OwnerUpdated(msg.sender, ownersToAdd, ownersToRemove);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃  Execution view functions   ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IMultiOwnerPlugin
    function eip712Domain()
        public
        view
        override
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        return (
            hex"1f", // 11111 indicate salt field is also used
            _NAME,
            _VERSION,
            block.chainid,
            msg.sender,
            _SALT,
            new uint256[](0)
        );
    }

    /// @inheritdoc IERC1271
    /// @dev The signature is valid if it is signed by one of the owners' private key
    /// (if the owner is an EOA) or if it is a valid ERC-1271 signature from one of the
    /// owners (if the owner is a contract). Note that unlike the signature
    /// validation used in `validateUserOp`, this does not wrap the digest in
    /// an "Ethereum Signed Message" envelope before checking the signature in
    /// the EOA-owner case.
    function isValidSignature(bytes32 digest, bytes memory signature) public view override returns (bytes4) {
        bytes32 messageHash = getMessageHash(msg.sender, abi.encode(digest));

        // try to recover through ECDSA
        (address signer, ECDSA.RecoverError error) = ECDSA.tryRecover(messageHash, signature);
        if (error == ECDSA.RecoverError.NoError && _owners.contains(msg.sender, CastLib.toSetValue(signer))) {
            return _1271_MAGIC_VALUE;
        }

        if (_isValidERC1271OwnerTypeSignature(msg.sender, messageHash, signature)) {
            return _1271_MAGIC_VALUE;
        }

        return _1271_MAGIC_VALUE_FAILURE;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IMultiOwnerPlugin
    function encodeMessageData(address account, bytes memory message)
        public
        view
        override
        returns (bytes memory)
    {
        bytes32 messageHash = keccak256(abi.encode(ERC6900_TYPEHASH, keccak256(message)));
        return abi.encodePacked("\x19\x01", _domainSeparator(account), messageHash);
    }

    /// @inheritdoc IMultiOwnerPlugin
    function getMessageHash(address account, bytes memory message) public view override returns (bytes32) {
        return keccak256(encodeMessageData(account, message));
    }

    /// @inheritdoc IMultiOwnerPlugin
    function isOwnerOf(address account, address ownerToCheck) public view returns (bool) {
        return _owners.contains(account, CastLib.toSetValue(ownerToCheck));
    }

    /// @inheritdoc IMultiOwnerPlugin
    function ownersOf(address account) public view returns (address[] memory) {
        return CastLib.toAddressArray(_owners.getAll(account));
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    /// @dev The owner array cannot have 0 or duplicated addresses.
    function _onInstall(bytes calldata data) internal override isNotInitialized(msg.sender) {
        (address[] memory initialOwners) = abi.decode(data, (address[]));
        if (initialOwners.length == 0) {
            revert EmptyOwnersNotAllowed();
        }
        _addOwnersOrRevert(_owners, msg.sender, initialOwners);

        emit OwnerUpdated(msg.sender, initialOwners, new address[](0));
    }

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {
        address[] memory ownersToRemove = ownersOf(msg.sender);
        emit OwnerUpdated(msg.sender, new address[](0), ownersToRemove);
        _owners.clear(msg.sender);
    }

    /// @inheritdoc BasePlugin
    /// @dev Since owner can be an ERC-1271 compliant contract, we won't know the format of the signatures.
    /// Therefore, any invalid signature are treated as mismatched signatures in the ERC-4337 context unless
    /// reverted in ERC-1271 owner signature validation.
    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION_OWNER)) {
            (address signer, ECDSA.RecoverError error) =
                userOpHash.toEthSignedMessageHash().tryRecover(userOp.signature);
            if (error == ECDSA.RecoverError.NoError && isOwnerOf(msg.sender, signer)) {
                return _SIG_VALIDATION_PASSED;
            }

            if (_isValidERC1271OwnerTypeSignature(msg.sender, userOpHash, userOp.signature)) {
                return _SIG_VALIDATION_PASSED;
            }

            return _SIG_VALIDATION_FAILED;
        }

        revert NotImplemented();
    }

    /// @inheritdoc BasePlugin
    function runtimeValidationFunction(uint8 functionId, address sender, uint256, bytes calldata)
        external
        view
        override
    {
        if (functionId == uint8(FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)) {
            // Validate that the sender is an owner of the account, or self.
            if (sender != msg.sender && !isOwnerOf(msg.sender, sender)) {
                revert NotAuthorized();
            }
        } else {
            revert NotImplemented();
        }
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](3);
        manifest.executionFunctions[0] = this.updateOwners.selector;
        manifest.executionFunctions[1] = this.eip712Domain.selector;
        manifest.executionFunctions[2] = this.isValidSignature.selector;

        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION_OWNER),
            dependencyIndex: 0 // Unused.
        });

        // Update Modular Account's native functions to use userOpValidationFunction provided by this plugin
        // The view functions `isValidSignature` and `eip712Domain` are excluded from being assigned a user
        // operation validation function since they should only be called via the runtime path.
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](6);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.updateOwners.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: UpgradeableModularAccount.installPlugin.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: UpgradeableModularAccount.uninstallPlugin.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[5] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        ManifestFunction memory ownerOrSelfRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF),
            dependencyIndex: 0 // Unused.
        });
        ManifestFunction memory alwaysAllowFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0, // Unused.
            dependencyIndex: 0 // Unused.
        });

        // Update Modular Account's native functions to use runtimeValidationFunction provided by this plugin
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](8);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.updateOwners.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: UpgradeableModularAccount.installPlugin.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: UpgradeableModularAccount.uninstallPlugin.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[5] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[6] = ManifestAssociatedFunction({
            executionSelector: this.isValidSignature.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[7] = ManifestAssociatedFunction({
            executionSelector: this.eip712Domain.selector,
            associatedFunction: alwaysAllowFunction
        });

        return manifest;
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;

        // Permission strings
        string memory modifyOwnershipPermission = "Modify Ownership";

        // Permission descriptions
        metadata.permissionDescriptors = new SelectorPermission[](1);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: this.updateOwners.selector,
            permissionDescription: modifyOwnershipPermission
        });

        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IMultiOwnerPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃   Internal    ┃
    // ┗━━━━━━━━━━━━━━━┛

    function _domainSeparator(address account) internal view returns (bytes32) {
        return keccak256(abi.encode(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION, block.chainid, account, _SALT));
    }

    function _addOwnersOrRevert(
        AssociatedLinkedListSet storage ownerSet,
        address associated,
        address[] memory ownersToAdd
    ) private {
        uint256 length = ownersToAdd.length;
        for (uint256 i = 0; i < length; ++i) {
            // Catches address(0), duplicated addresses
            if (!ownerSet.tryAdd(associated, CastLib.toSetValue(ownersToAdd[i]))) {
                revert InvalidOwner(ownersToAdd[i]);
            }
        }
    }

    function _removeOwnersOrRevert(
        AssociatedLinkedListSet storage ownerSet,
        address associated,
        address[] memory ownersToRemove
    ) private {
        uint256 length = ownersToRemove.length;
        for (uint256 i = 0; i < length; ++i) {
            if (!ownerSet.tryRemove(associated, CastLib.toSetValue(ownersToRemove[i]))) {
                revert OwnerDoesNotExist(ownersToRemove[i]);
            }
        }
    }

    function _isValidERC1271OwnerTypeSignature(address associated, bytes32 digest, bytes memory signature)
        private
        view
        returns (bool)
    {
        address[] memory owners_ = ownersOf(associated);
        uint256 length = owners_.length;
        for (uint256 i = 0; i < length; ++i) {
            if (SignatureChecker.isValidERC1271SignatureNow(owners_[i], digest, signature)) {
                return true;
            }
        }
        return false;
    }

    /// @inheritdoc BasePlugin
    function _isInitialized(address account) internal view override returns (bool) {
        return !_owners.isEmpty(account);
    }
}
