// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";

import {BaseModule} from "../../modules/BaseModule.sol";

/// @title Allowlist Module
/// @author Alchemy
/// @notice This module allows for the setting and enforcement of allowlists for validation functions. These
/// allowlists can specify which addresses can be called by the validation function, and optionally which selectors
/// can be called on those addresses. These restrictions only apply to the `IModularAccount.execute` and
/// `IModularAccount.executeBatch` functions.
contract AllowlistModule is IValidationHookModule, BaseModule {
    struct AllowlistInit {
        address target;
        bool hasSelectorAllowlist;
        bytes4[] selectors;
    }

    struct AllowlistEntry {
        bool allowed;
        bool hasSelectorAllowlist;
    }

    mapping(uint32 entityId => mapping(address target => mapping(address account => AllowlistEntry))) public
        targetAllowlist;
    mapping(
        uint32 entityId => mapping(address target => mapping(bytes4 selector => mapping(address account => bool)))
    ) public selectorAllowlist;

    event AllowlistTargetUpdated(
        uint32 indexed entityId, address indexed account, address indexed target, AllowlistEntry entry
    );
    event AllowlistSelectorUpdated(
        uint32 indexed entityId, address indexed account, bytes24 indexed targetAndSelector, bool allowed
    );

    error TargetNotAllowed();
    error SelectorNotAllowed();
    error NoSelectorSpecified();

    /// @inheritdoc IModule
    /// @dev The `data` parameter is expected to be encoded as `(uint32 entityId, AllowlistInit[] init)`.
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, AllowlistInit[] memory init) = abi.decode(data, (uint32, AllowlistInit[]));

        for (uint256 i = 0; i < init.length; i++) {
            setAllowlistTarget(entityId, init[i].target, true, init[i].hasSelectorAllowlist);

            if (init[i].hasSelectorAllowlist) {
                for (uint256 j = 0; j < init[i].selectors.length; j++) {
                    setAllowlistSelector(entityId, init[i].target, init[i].selectors[j], true);
                }
            }
        }
    }

    /// @inheritdoc IModule
    /// @dev The `data` parameter is expected to be encoded as `(uint32 entityId, AllowlistInit[] init)`.
    function onUninstall(bytes calldata data) external override {
        (uint32 entityId, AllowlistInit[] memory init) = abi.decode(data, (uint32, AllowlistInit[]));

        batchInitAllowlist(entityId, init);
    }

    /// @inheritdoc IValidationHookModule
    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
        external
        view
        override
        returns (uint256)
    {
        checkAllowlistCalldata(entityId, userOp.callData);
        return 0;
    }

    /// @inheritdoc IValidationHookModule
    function preRuntimeValidationHook(uint32 entityId, address, uint256, bytes calldata data, bytes calldata)
        external
        view
        override
    {
        checkAllowlistCalldata(entityId, data);
        return;
    }

    // solhint-disable-next-line no-empty-blocks
    function preSignatureValidationHook(uint32, address, bytes32, bytes calldata) external pure override {}

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "alchemy.allowlist-module.0.0.1";
    }

    /// @notice Batch initialize the allowlist for a given entity ID.
    /// @param entityId The entity ID to initialize the allowlist for.
    /// @param init The allowlist initialization data.
    function batchInitAllowlist(uint32 entityId, AllowlistInit[] memory init) public {
        for (uint256 i = 0; i < init.length; i++) {
            setAllowlistTarget(entityId, init[i].target, false, false);

            if (init[i].hasSelectorAllowlist) {
                for (uint256 j = 0; j < init[i].selectors.length; j++) {
                    setAllowlistSelector(entityId, init[i].target, init[i].selectors[j], false);
                }
            }
        }
    }

    /// @notice Set the allowlist status for a target address, in the allowlist of the caller account and the
    /// provided entity ID.
    /// @param entityId The entity ID to set the allowlist status for.
    /// @param target The target address.
    /// @param allowed The new allowlist status, indicating whether or not the target address can be called.
    /// @param hasSelectorAllowlist Whether or not the target address has a selector allowlist. If true, the
    /// allowlist checking will validate that the selector is on the selector allowlist.
    function setAllowlistTarget(uint32 entityId, address target, bool allowed, bool hasSelectorAllowlist) public {
        AllowlistEntry memory entry = AllowlistEntry(allowed, hasSelectorAllowlist);
        targetAllowlist[entityId][target][msg.sender] = entry;
        emit AllowlistTargetUpdated(entityId, msg.sender, target, entry);
    }

    /// @notice Set the allowlist status for a selector, in the allowlist of the caller account and the provided
    /// entity ID. Note that if the target address does not have a selector allowlist, this update will not be
    /// reflected on the usage of the allowlist hook.
    /// @param entityId The entity ID to set the allowlist status for.
    /// @param target The target address.
    /// @param selector The selector to set the allowlist status for.
    /// @param allowed The new allowlist status, indicating whether or not the selector can be called.
    function setAllowlistSelector(uint32 entityId, address target, bytes4 selector, bool allowed) public {
        selectorAllowlist[entityId][target][selector][msg.sender] = allowed;
        bytes24 targetAndSelector = bytes24(bytes24(bytes20(target)) | (bytes24(selector) >> 160));
        emit AllowlistSelectorUpdated(entityId, msg.sender, targetAndSelector, allowed);
    }

    /// @notice Check the allowlist status for a call payload. If the call is not allowed, this function will
    /// revert.
    /// @param entityId The entity ID to check the allowlist status for.
    /// @param callData The call payload to check the allowlist status for. This should be a call to either
    /// `IModularAccount.execute`, or `IModularAccount.executeBatch`.
    function checkAllowlistCalldata(uint32 entityId, bytes calldata callData) public view {
        if (bytes4(callData[:4]) == IModularAccount.execute.selector) {
            (address target,, bytes memory data) = abi.decode(callData[4:], (address, uint256, bytes));
            _checkCallPermission(entityId, msg.sender, target, data);
        } else if (bytes4(callData[:4]) == IModularAccount.executeBatch.selector) {
            Call[] memory calls = abi.decode(callData[4:], (Call[]));

            for (uint256 i = 0; i < calls.length; i++) {
                _checkCallPermission(entityId, msg.sender, calls[i].target, calls[i].data);
            }
        }
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(BaseModule, IERC165)
        returns (bool)
    {
        return interfaceId == type(IValidationHookModule).interfaceId || super.supportsInterface(interfaceId);
    }

    function _checkCallPermission(uint32 entityId, address account, address target, bytes memory data)
        internal
        view
    {
        AllowlistEntry storage entry = targetAllowlist[entityId][target][account];
        (bool allowed, bool hasSelectorAllowlist) = (entry.allowed, entry.hasSelectorAllowlist);

        if (!allowed) {
            revert TargetNotAllowed();
        }

        if (hasSelectorAllowlist) {
            if (data.length < 4) {
                revert NoSelectorSpecified();
            }

            bytes4 selector = bytes4(data);

            if (!selectorAllowlist[entityId][target][selector][account]) {
                revert SelectorNotAllowed();
            }
        }
    }
}
