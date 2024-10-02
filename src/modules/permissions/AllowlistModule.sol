// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";

import {BaseModule} from "../../modules/BaseModule.sol";

/// @title Allowlist Module
/// @author Alchemy
/// @notice This module allows for the setting and enforcement of allowlists for validation functions.
///    - These allowlists can specify which addresses and or selectors can be called by the validation function. It
/// supports:
///       - specific addresss + specific selectors
///       - specific addresss + any selectors
///       - any addresss + specific selectors
///    - These restrictions only apply to the `IModularAccount.execute` and `IModularAccount.executeBatch`
/// functions.
///    - The order of permission checking:
///       - if wildcard selecor (any address allowed), pass
///       - if wildcard address (any selector allowed), pass
///       - if sepecific address + sepecific selector, pass
///       - revert all other cases
contract AllowlistModule is IValidationHookModule, BaseModule {
    struct AllowlistInput {
        address target;
        // if target is address(0), hasSelectorAllowlist is ignored.
        bool hasSelectorAllowlist;
        bytes4[] selectors;
    }

    struct AddressAllowlistEntry {
        bool allowed;
        bool hasSelectorAllowlist;
    }

    mapping(uint32 entityId => mapping(address target => mapping(address account => AddressAllowlistEntry))) public
        addressAllowlist;

    /// @notice if target is address(0), any address is allowed with the selector
    mapping(
        uint32 entityId => mapping(bytes4 selector => mapping(address target => mapping(address account => bool)))
    ) public selectorAllowlist;

    event AddressAllowlistUpdated(
        uint32 indexed entityId, address indexed account, address indexed target, AddressAllowlistEntry entry
    );
    event SelectorAllowlistUpdated(
        uint32 indexed entityId, address indexed account, bytes24 indexed targetAndSelector, bool allowed
    );

    error AddressNotAllowed();
    error SelectorNotAllowed();
    error NoSelectorSpecified();

    /// @inheritdoc IModule
    /// @dev The `data` parameter is expected to be encoded as `(uint32 entityId, AllowlistInput[] inputs)`.
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, AllowlistInput[] memory inputs) = abi.decode(data, (uint32, AllowlistInput[]));

        updateAllowlist(entityId, inputs);
    }

    /// @inheritdoc IModule
    /// @dev The `data` parameter is expected to be encoded as `(uint32 entityId, AllowlistInput[] inputs)`.
    function onUninstall(bytes calldata data) external override {
        (uint32 entityId, AllowlistInput[] memory inputs) = abi.decode(data, (uint32, AllowlistInput[]));

        deleteAllowlist(entityId, inputs);
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

    /// @notice update the allowlists for a given entity ID. If the entry for an address or selector exist, it will
    /// be overwritten.
    /// @param entityId The entity ID to initialize the allowlist for.
    /// @param inputs The allowlist inputs data to update.
    function updateAllowlist(uint32 entityId, AllowlistInput[] memory inputs) public {
        for (uint256 i = 0; i < inputs.length; i++) {
            AllowlistInput memory input = inputs[i];
            if (input.target == address(0)) {
                // wildcard case for selectors, any address can be called for the selector
                for (uint256 j = 0; j < input.selectors.length; j++) {
                    setSelectorAllowlist(entityId, input.target, input.selectors[j], true);
                }
            } else {
                setAddressAllowlist(entityId, input.target, true, input.hasSelectorAllowlist);

                if (input.hasSelectorAllowlist) {
                    for (uint256 j = 0; j < input.selectors.length; j++) {
                        setSelectorAllowlist(entityId, input.target, input.selectors[j], true);
                    }
                }
            }
        }
    }

    /// @notice delete the allowlists for a given entity ID.
    /// @param entityId The entity ID to initialize the allowlist for.
    /// @param inputs The allowlist inputs data to update.
    function deleteAllowlist(uint32 entityId, AllowlistInput[] memory inputs) public {
        for (uint256 i = 0; i < inputs.length; i++) {
            AllowlistInput memory input = inputs[i];
            if (input.target == address(0)) {
                // wildcard case for selectors, any address can be called for the selector
                for (uint256 j = 0; j < input.selectors.length; j++) {
                    setSelectorAllowlist(entityId, input.target, input.selectors[j], false);
                }
            } else {
                setAddressAllowlist(entityId, input.target, false, false);

                if (input.hasSelectorAllowlist) {
                    for (uint256 j = 0; j < input.selectors.length; j++) {
                        setSelectorAllowlist(entityId, input.target, input.selectors[j], false);
                    }
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
    function setAddressAllowlist(uint32 entityId, address target, bool allowed, bool hasSelectorAllowlist)
        public
    {
        AddressAllowlistEntry memory entry = AddressAllowlistEntry(allowed, hasSelectorAllowlist);
        addressAllowlist[entityId][target][msg.sender] = entry;
        emit AddressAllowlistUpdated(entityId, msg.sender, target, entry);
    }

    /// @notice Set the allowlist status for a selector, in the allowlist of the caller account and the provided
    /// entity ID.
    /// Note that if the target address does not have a selector allowlist, this update will not be
    /// reflected on the usage of the allowlist hook.
    /// @param entityId The entity ID to set the allowlist status for.
    /// @param target The target address.
    /// @param selector The selector to set the allowlist status for.
    /// @param allowed The new allowlist status, indicating whether or not the selector can be called.
    function setSelectorAllowlist(uint32 entityId, address target, bytes4 selector, bool allowed) public {
        selectorAllowlist[entityId][selector][target][msg.sender] = allowed;
        bytes24 targetAndSelector = bytes24(bytes24(bytes20(target)) | (bytes24(selector) >> 160));
        emit SelectorAllowlistUpdated(entityId, msg.sender, targetAndSelector, allowed);
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
        if (data.length < 4) {
            revert NoSelectorSpecified();
        }

        bytes4 selector = bytes4(data);
        if (selectorAllowlist[entityId][selector][address(0)][account]) {
            // selector wildcard case, any address is allowed
            return;
        }

        AddressAllowlistEntry storage entry = addressAllowlist[entityId][target][account];
        (bool allowed, bool hasSelectorAllowlist) = (entry.allowed, entry.hasSelectorAllowlist);

        if (!allowed) {
            revert AddressNotAllowed();
        }

        if (hasSelectorAllowlist) {
            if (!selectorAllowlist[entityId][selector][target][account]) {
                revert SelectorNotAllowed();
            }
        }
    }
}
