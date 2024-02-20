// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.22;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {CastLib} from "../../helpers/CastLib.sol";
import {UserOperation} from "../../interfaces/erc4337/UserOperation.sol";
import {IPlugin} from "../../interfaces/IPlugin.sol";
import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata,
    SelectorPermission
} from "../../interfaces/IPlugin.sol";
import {IPluginExecutor} from "../../interfaces/IPluginExecutor.sol";
import {Call, IStandardExecutor} from "../../interfaces/IStandardExecutor.sol";
import {
    AssociatedLinkedListSet, AssociatedLinkedListSetLib
} from "../../libraries/AssociatedLinkedListSetLib.sol";
import {
    SetValue, SENTINEL_VALUE, SIG_VALIDATION_PASSED, SIG_VALIDATION_FAILED
} from "../../libraries/Constants.sol";
import {BasePlugin} from "../BasePlugin.sol";
import {ISessionKeyPlugin} from "./ISessionKeyPlugin.sol";
import {SessionKeyPermissions} from "./permissions/SessionKeyPermissions.sol";

/// @title Session Key Plugin
/// @author Alchemy
/// @notice This plugin allows users to set session keys that can be used to validate user operations performing
/// external calls. It also implements customizable permissions for session keys, supporting:
/// - Allowlist/denylist on addresses and function selectors.
/// - Time range for when a session key may be used.
/// - Spend limits on native token and ERC-20 tokens.
/// - Gas spend limits, either from the account's balance or from a specified paymaster.
contract SessionKeyPlugin is ISessionKeyPlugin, SessionKeyPermissions, BasePlugin {
    using ECDSA for bytes32;
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;

    string internal constant _NAME = "Session Key Plugin";
    string internal constant _VERSION = "1.0.1";
    string internal constant _AUTHOR = "Alchemy";

    // Constants used in the manifest
    uint256 internal constant _MANIFEST_DEPENDENCY_INDEX_OWNER_RUNTIME_VALIDATION = 0;
    uint256 internal constant _MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION = 1;

    // Storage fields
    AssociatedLinkedListSet internal _sessionKeys;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISessionKeyPlugin
    function executeWithSessionKey(Call[] calldata calls, address sessionKey)
        external
        override
        returns (bytes[] memory)
    {
        _updateLimitsPreExec(msg.sender, calls, sessionKey);

        uint256 callsLength = calls.length;
        bytes[] memory results = new bytes[](callsLength);

        for (uint256 i = 0; i < callsLength; ++i) {
            Call calldata call = calls[i];

            results[i] = IPluginExecutor(msg.sender).executeFromPluginExternal(call.target, call.value, call.data);
        }

        return results;
    }

    /// @inheritdoc ISessionKeyPlugin
    function addSessionKey(address sessionKey, bytes32 tag, bytes[] calldata permissionUpdates) public override {
        if (!_sessionKeys.tryAdd(msg.sender, CastLib.toSetValue(sessionKey))) {
            // This check ensures no duplicate keys and that the session key is not the zero address.
            revert InvalidSessionKey(sessionKey);
        }

        // Register the key with a new ID, and update the ID counter
        // We use pre increment to prevent the first id from being zero.
        // We don't need to check whether or not the session key id exists, because we know it to be atomic with
        // add/remove operations on the _sessionKeys storage variable, and therefore must not be registered.
        _updateSessionKeyId(msg.sender, sessionKey, SessionKeyId.wrap(bytes32(++_keyIdCounter[msg.sender])));

        emit SessionKeyAdded(msg.sender, sessionKey, tag);

        if (permissionUpdates.length > 0) {
            // Call the public function internally to update the permissions.
            updateKeyPermissions(sessionKey, permissionUpdates);
        }
    }

    /// @inheritdoc ISessionKeyPlugin
    function removeSessionKey(address sessionKey, bytes32 predecessor) external override {
        if (!_sessionKeys.tryRemoveKnown(msg.sender, CastLib.toSetValue(sessionKey), predecessor)) {
            revert InvalidSessionKey(sessionKey);
        }

        // Unset the key id for the session key.
        // We don't need to check that the key exists, because we know it to be atomic with add/remove operations
        // on the _sessionKeys storage variable, and therefore must be registered.
        _updateSessionKeyId(msg.sender, sessionKey, SessionKeyId.wrap(bytes32(0)));

        emit SessionKeyRemoved(msg.sender, sessionKey);
    }

    /// @inheritdoc ISessionKeyPlugin
    function rotateSessionKey(address oldSessionKey, bytes32 predecessor, address newSessionKey)
        external
        override
    {
        if (!_sessionKeys.tryRemoveKnown(msg.sender, CastLib.toSetValue(oldSessionKey), predecessor)) {
            revert InvalidSessionKey(oldSessionKey);
        }

        // If the new key to rotate into is a duplicate or the zero address, revert.
        if (!_sessionKeys.tryAdd(msg.sender, CastLib.toSetValue(newSessionKey))) {
            revert InvalidSessionKey(newSessionKey);
        }

        SessionKeyId oldSessionKeyId = _sessionKeyIdOf(msg.sender, oldSessionKey);
        _updateSessionKeyId(msg.sender, oldSessionKey, SessionKeyId.wrap(bytes32(0)));
        _updateSessionKeyId(msg.sender, newSessionKey, oldSessionKeyId);

        emit SessionKeyRotated(msg.sender, oldSessionKey, newSessionKey);
    }

    // The function `updateKeyPermissions` is implemented in `SessionKeyPermissions`.

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin only state updating functions       ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    // The function `resetSessionKeyGasLimitTimestamp` is implemented in `SessionKeyPermissions`.

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {
        // Unset the key id for all session keys.
        address[] memory sessionKeys = CastLib.toAddressArray(_sessionKeys.getAll(msg.sender));
        uint256 length = sessionKeys.length;
        for (uint256 i = 0; i < length; ++i) {
            _updateSessionKeyId(msg.sender, sessionKeys[i], SessionKeyId.wrap(bytes32(0)));

            emit SessionKeyRemoved(msg.sender, sessionKeys[i]);
        }

        _sessionKeys.clear(msg.sender);
        // Note that we do not reset the key id counter `_keyIdCounter` for the account, in order to prevent
        // permissions configured from a previous installation from being re-used.
    }

    /// @inheritdoc BasePlugin
    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION_SESSION_KEY)) {
            (Call[] memory calls, address sessionKey) = abi.decode(userOp.callData[4:], (Call[], address));
            bytes32 hash = userOpHash.toEthSignedMessageHash();

            (address recoveredSig, ECDSA.RecoverError err) = hash.tryRecover(userOp.signature);
            if (err != ECDSA.RecoverError.NoError) {
                revert InvalidSignature(sessionKey);
            }

            if (!_sessionKeys.contains(msg.sender, CastLib.toSetValue(sessionKey))) {
                revert PermissionsCheckFailed();
            }

            uint256 validation = _checkUserOpPermissions(userOp, calls, sessionKey);
            if (uint160(validation) != uint160(SIG_VALIDATION_PASSED)) {
                revert PermissionsCheckFailed();
            }
            // return SIG_VALIDATION_FAILED on sig validation failure only, all other failure modes should revert
            return validation | (sessionKey == recoveredSig ? SIG_VALIDATION_PASSED : SIG_VALIDATION_FAILED);
        }
        revert NotImplemented(msg.sig, functionId);
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.dependencyInterfaceIds = new bytes4[](2);
        manifest.dependencyInterfaceIds[_MANIFEST_DEPENDENCY_INDEX_OWNER_RUNTIME_VALIDATION] =
            type(IPlugin).interfaceId;
        manifest.dependencyInterfaceIds[_MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION] =
            type(IPlugin).interfaceId;

        manifest.executionFunctions = new bytes4[](5);
        manifest.executionFunctions[0] = this.executeWithSessionKey.selector;
        manifest.executionFunctions[1] = this.addSessionKey.selector;
        manifest.executionFunctions[2] = this.removeSessionKey.selector;
        manifest.executionFunctions[3] = this.rotateSessionKey.selector;
        manifest.executionFunctions[4] = this.updateKeyPermissions.selector;

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

        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](5);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.executeWithSessionKey.selector,
            associatedFunction: sessionKeyUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.addSessionKey.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.removeSessionKey.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: this.rotateSessionKey.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: this.updateKeyPermissions.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        // Session keys are only expected to be used for user op validation, so no runtime validation functions are
        // set over executeWithSessionKey, and pre runtime hook will always deny.
        ManifestFunction memory ownerRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // unused since it's a dependency
            dependencyIndex: _MANIFEST_DEPENDENCY_INDEX_OWNER_RUNTIME_VALIDATION
        });

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](4);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.addSessionKey.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.removeSessionKey.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.rotateSessionKey.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: this.updateKeyPermissions.selector,
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
        string memory modifySessionKeys = "Modify Session Keys";
        string memory modifySessionKeyPermissions = "Modify Session Key Permissions";

        // Permission descriptions
        metadata.permissionDescriptors = new SelectorPermission[](4);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: this.addSessionKey.selector,
            permissionDescription: modifySessionKeys
        });
        metadata.permissionDescriptors[1] = SelectorPermission({
            functionSelector: this.removeSessionKey.selector,
            permissionDescription: modifySessionKeys
        });
        metadata.permissionDescriptors[2] = SelectorPermission({
            functionSelector: this.rotateSessionKey.selector,
            permissionDescription: modifySessionKeys
        });
        metadata.permissionDescriptors[3] = SelectorPermission({
            functionSelector: this.updateKeyPermissions.selector,
            permissionDescription: modifySessionKeyPermissions
        });

        return metadata;
    }

    /// @inheritdoc BasePlugin
    function _onInstall(bytes calldata data) internal override isNotInitialized(msg.sender) {
        (address[] memory sessionKeysToAdd, bytes32[] memory tags,) =
            abi.decode(data, (address[], bytes32[], bytes[][]));

        // Permission updates depend on `calldata` types for the updates, in order to use array slices.
        // Unfortunately, solidity does not support `abi.decode` outputting calldata types, so we do it manually.
        // The prior `abi.decode` call validates that `data` has a valid encoding of a `bytes[][]` at this
        // position, so we can load in the offset and length of the `bytes[][]` directly.
        bytes[][] calldata permissionUpdates;
        assembly ("memory-safe") {
            // Get the offset of the bytes[][] used for permissions updates. The offset for this field is stored at
            // the third word of `data`. Note that `data.offset` refers to the start of the actual data contents,
            // one word after the length.
            let permissionUpdatesRelativeOffset := calldataload(add(data.offset, 0x40))
            // We now have the relative offset of the bytes[][] in `data`. We need to add the starting offset
            // (aka `data.offset`) to get the absolute offset.
            let permissionUpdatesLengthOffset := add(data.offset, permissionUpdatesRelativeOffset)
            // Note that solidity expects the field `var.offset` to point to the start of the actual data contents,
            // one word after the length. Therefore, we add 0x20 here to get the correct offset.
            permissionUpdates.offset := add(0x20, permissionUpdatesLengthOffset)
            // Load the length of the bytes[][].
            permissionUpdates.length := calldataload(permissionUpdatesLengthOffset)
        }

        uint256 length = sessionKeysToAdd.length;

        if (length != tags.length || length != permissionUpdates.length) {
            revert LengthMismatch();
        }

        for (uint256 i = 0; i < length; ++i) {
            // Use the public function to add the session key, set the key id, emit the event, and update the
            // permissions.
            addSessionKey(sessionKeysToAdd[i], tags[i], permissionUpdates[i]);
        }
    }
    /// @inheritdoc BasePlugin

    function _isInitialized(address account) internal view override returns (bool) {
        return !_sessionKeys.isEmpty(account);
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(ISessionKeyPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin only view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISessionKeyPlugin
    function sessionKeysOf(address account) external view override returns (address[] memory) {
        SetValue[] memory values = _sessionKeys.getAll(account);

        return CastLib.toAddressArray(values);
    }

    /// @inheritdoc ISessionKeyPlugin
    function isSessionKeyOf(address account, address sessionKey) external view override returns (bool) {
        return _sessionKeys.contains(account, CastLib.toSetValue(sessionKey));
    }

    /// @inheritdoc ISessionKeyPlugin
    function findPredecessor(address account, address sessionKey) external view override returns (bytes32) {
        address[] memory sessionKeys = CastLib.toAddressArray(_sessionKeys.getAll(account));

        uint256 length = sessionKeys.length;
        bytes32 predecessor = SENTINEL_VALUE;
        for (uint256 i = 0; i < length; ++i) {
            if (sessionKeys[i] == sessionKey) {
                return predecessor;
            }

            predecessor = bytes32(bytes20(sessionKeys[i]));
        }

        revert SessionKeyNotFound(sessionKey);
    }
}
