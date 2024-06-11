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
contract SessionKeyPlugin is ISessionKeyPlugin, SessionKeyPermissions {
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
    function executeWithSessionKey(Call[] calldata calls, address sessionKey) external returns (bytes[] memory) {
        _updateLimitsPreExec(msg.sender, calls, sessionKey);

        uint256 callsLength = calls.length;
        bytes[] memory results = new bytes[](callsLength);

        for (uint256 i = 0; i < callsLength; ++i) {
            Call calldata call = calls[i];

            results[i] = IPluginExecutor(msg.sender).executeFromPluginExternal(call.target, call.value, call.data);
        }

        return results;
    }

    // The function `updateKeyPermissions` is implemented in `SessionKeyPermissions`.

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin only state updating functions       ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    // The function `resetSessionKeyGasLimitTimestamp` is implemented in `SessionKeyPermissions`.

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION_SESSION_KEY)) {
            (Call[] memory calls, address sessionKey) = abi.decode(userOp.callData[4:], (Call[], address));
            bytes32 hash = userOpHash.toEthSignedMessageHash();

            (address recoveredSig, ECDSA.RecoverError err) = hash.tryRecover(userOp.signature);
            if (err != ECDSA.RecoverError.NoError) {
                revert("Signature does not match session key");
            }

            if (!_sessionKeys.contains(msg.sender, CastLib.toSetValue(sessionKey))) {
                revert("Unknown session key");
            }

            uint256 validation = _checkUserOpPermissions(userOp, calls, sessionKey);
            // return SIG_VALIDATION_FAILED on sig validation failure only, all other failure modes should revert
            return validation | (sessionKey == recoveredSig ? SIG_VALIDATION_PASSED : SIG_VALIDATION_FAILED);
        }
        revert("Wrong function id for validation");
    }
}
