// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {BasePlugin} from "../BasePlugin.sol";
import {ISessionKeyPlugin} from "./ISessionKeyPlugin.sol";

import {IPlugin} from "../../interfaces/IPlugin.sol";
import {IPluginExecutor} from "../../interfaces/IPluginExecutor.sol";
import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata,
    SelectorPermission
} from "../../interfaces/IPlugin.sol";
import {Call, IStandardExecutor} from "../../interfaces/IStandardExecutor.sol";
import {UserOperation} from "../../interfaces/erc4337/UserOperation.sol";

import {
    AssociatedLinkedListSet, AssociatedLinkedListSetLib
} from "../../libraries/AssociatedLinkedListSetLib.sol";
import {CastLib} from "../../libraries/CastLib.sol";
import {SetValue, SENTINEL_VALUE} from "../../libraries/LinkedListSetUtils.sol";

/// @title Session Key Plugin
/// @author Alchemy
/// @notice This plugin allows users to set session keys that can be used to validate user operations performing
/// external calls. It does not enforce any permissions on what the keys can do, that must be configured via other
/// plugins with hooks.
contract SessionKeyPlugin is BasePlugin, ISessionKeyPlugin {
    using ECDSA for bytes32;
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;

    string internal constant _NAME = "Session Key Plugin";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "Alchemy";

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // Constants used in the manifest
    uint256 internal constant _MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION = 0;
    uint256 internal constant _MANIFEST_DEPENDENCY_INDEX_OWNER_RUNTIME_VALIDATION = 1;

    AssociatedLinkedListSet internal _sessionKeys;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISessionKeyPlugin
    function executeWithSessionKey(Call[] calldata calls, address) external returns (bytes[] memory) {
        uint256 callsLength = calls.length;
        bytes[] memory results = new bytes[](callsLength);

        for (uint256 i = 0; i < callsLength;) {
            Call calldata call = calls[i];

            results[i] = IPluginExecutor(msg.sender).executeFromPluginExternal(call.target, call.value, call.data);

            unchecked {
                ++i;
            }
        }

        return results;
    }

    /// @inheritdoc ISessionKeyPlugin
    function getSessionKeys() external view returns (address[] memory) {
        SetValue[] memory values = _sessionKeys.getAll(msg.sender);

        return CastLib.toAddressArray(values);
    }

    /// @inheritdoc ISessionKeyPlugin
    function isSessionKey(address sessionKey) external view returns (bool) {
        return _sessionKeys.contains(msg.sender, CastLib.toSetValue(sessionKey));
    }

    /// @inheritdoc ISessionKeyPlugin
    function updateSessionKeys(
        address[] calldata sessionKeysToAdd,
        SessionKeyToRemove[] calldata sessionKeysToRemove
    ) external {
        uint256 length = sessionKeysToRemove.length;
        for (uint256 i = 0; i < length;) {
            if (
                !_sessionKeys.tryRemoveKnown(
                    msg.sender,
                    CastLib.toSetValue(sessionKeysToRemove[i].sessionKey),
                    sessionKeysToRemove[i].predecessor
                )
            ) {
                revert UnableToRemove(sessionKeysToRemove[i].sessionKey);
            }

            unchecked {
                ++i;
            }
        }

        length = sessionKeysToAdd.length;
        for (uint256 i = 0; i < length;) {
            // This also checks that sessionKeysToAdd[i] is not zero.
            if (!_sessionKeys.tryAdd(msg.sender, CastLib.toSetValue(sessionKeysToAdd[i]))) {
                revert InvalidSessionKey(sessionKeysToAdd[i]);
            }

            unchecked {
                ++i;
            }
        }
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISessionKeyPlugin
    function sessionKeysOf(address account) external view returns (address[] memory) {
        SetValue[] memory values = _sessionKeys.getAll(account);

        return CastLib.toAddressArray(values);
    }

    /// @inheritdoc ISessionKeyPlugin
    function isSessionKeyOf(address account, address sessionKey) external view returns (bool) {
        return _sessionKeys.contains(account, CastLib.toSetValue(sessionKey));
    }

    /// @inheritdoc ISessionKeyPlugin
    function findPredecessor(address account, address sessionKey) external view returns (bytes32) {
        address[] memory sessionKeys = CastLib.toAddressArray(_sessionKeys.getAll(account));

        uint256 length = sessionKeys.length;
        bytes32 predecessor = SENTINEL_VALUE;
        for (uint256 i = 0; i < length;) {
            if (sessionKeys[i] == sessionKey) {
                return predecessor;
            }

            predecessor = bytes32(bytes20(sessionKeys[i]));

            unchecked {
                ++i;
            }
        }

        revert SessionKeyNotFound(sessionKey);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION_SESSION_KEY)) {
            (, address sessionKey) = abi.decode(userOp.callData[4:], (Call[], address));
            bytes32 hash = userOpHash.toEthSignedMessageHash();

            if (_sessionKeys.contains(msg.sender, CastLib.toSetValue(sessionKey))) {
                (address recoveredSig, ECDSA.RecoverError err) = hash.tryRecover(userOp.signature);
                if (err == ECDSA.RecoverError.NoError && sessionKey == recoveredSig) {
                    return _SIG_VALIDATION_PASSED;
                }
            }
            return _SIG_VALIDATION_FAILED;
        }
        revert NotImplemented();
    }

    /// @inheritdoc BasePlugin
    function _onInstall(bytes calldata data) internal override isNotInitialized(msg.sender) {
        address[] memory sessionKeysToAdd = abi.decode(data, (address[]));

        uint256 length = sessionKeysToAdd.length;
        for (uint256 i = 0; i < length;) {
            // This also checks that sessionKeysToAdd[i] is not zero.
            if (!_sessionKeys.tryAdd(msg.sender, CastLib.toSetValue(sessionKeysToAdd[i]))) {
                revert InvalidSessionKey(sessionKeysToAdd[i]);
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {
        _sessionKeys.clear(msg.sender);
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.dependencyInterfaceIds = new bytes4[](2);
        manifest.dependencyInterfaceIds[_MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION] =
            type(IPlugin).interfaceId;
        manifest.dependencyInterfaceIds[_MANIFEST_DEPENDENCY_INDEX_OWNER_RUNTIME_VALIDATION] =
            type(IPlugin).interfaceId;

        manifest.executionFunctions = new bytes4[](4);
        manifest.executionFunctions[0] = this.executeWithSessionKey.selector;
        manifest.executionFunctions[1] = this.getSessionKeys.selector;
        manifest.executionFunctions[2] = this.isSessionKey.selector;
        manifest.executionFunctions[3] = this.updateSessionKeys.selector;

        ManifestFunction memory sessionKeyUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION_SESSION_KEY),
            dependencyIndex: 0 // Unused.
        });
        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // unused since it's a dependency
            dependencyIndex: _MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION
        });

        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](2);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.executeWithSessionKey.selector,
            associatedFunction: sessionKeyUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.updateSessionKeys.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        // Session keys are only expected to be used for user op validation, so no runtime validation functions are
        // set over executeWithSessionKey, and pre runtime hook will always deny.
        ManifestFunction memory alwaysAllowValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0, // Unused.
            dependencyIndex: 0 // Unused.
        });

        ManifestFunction memory ownerRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // unused since it's a dependency
            dependencyIndex: _MANIFEST_DEPENDENCY_INDEX_OWNER_RUNTIME_VALIDATION
        });

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](3);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.getSessionKeys.selector,
            associatedFunction: alwaysAllowValidationFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.isSessionKey.selector,
            associatedFunction: alwaysAllowValidationFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.updateSessionKeys.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });

        manifest.preRuntimeValidationHooks = new ManifestAssociatedFunction[](1);
        manifest.preRuntimeValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.executeWithSessionKey.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.permitAnyExternalAddress = true;
        manifest.canSpendNativeToken = true;

        return manifest;
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;

        // Permission strings
        string memory modifyOwnershipPermission = "Modify Session Keys";

        // Permission descriptions
        metadata.permissionDescriptors = new SelectorPermission[](1);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: this.updateSessionKeys.selector,
            permissionDescription: modifyOwnershipPermission
        });

        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(ISessionKeyPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    /// @inheritdoc BasePlugin
    function _isInitialized(address account) internal view override returns (bool) {
        return !_sessionKeys.isEmpty(account);
    }
}
