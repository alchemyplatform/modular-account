// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.26;

import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {ERC165, IERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";

/// @title Base contract for modules
/// @dev Implements ERC-165 to support IModule's interface, which is a requirement
/// for module installation. This also ensures that module interactions cannot
/// happen via the standard execution funtions `execute` and `executeBatch`.
abstract contract BaseModule is ERC165, IModule {
    error NotImplemented();
    error UnexpectedValidationData();

    modifier noValidationData(bytes calldata validationData) {
        if (validationData.length > 0) {
            revert UnexpectedValidationData();
        }
        _;
    }

    /// @dev Returns true if this contract implements the interface defined by
    /// `interfaceId`. See the corresponding
    /// https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
    /// to learn more about how these ids are created.
    ///
    /// This function call must use less than 30 000 gas.
    ///
    /// Supporting the IModule interface is a requirement for module installation. This is also used
    /// by the modular account to prevent standard execution functions `execute` and `executeBatch` from
    /// making calls to modules.
    /// @param interfaceId The interface ID to check for support.
    /// @return True if the contract supports `interfaceId`.
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IModule).interfaceId || super.supportsInterface(interfaceId);
    }

    function _getSelectorAndCalldata(bytes calldata data) internal pure returns (bytes4, bytes memory) {
        if (bytes4(data[:4]) == IAccountExecute.executeUserOp.selector) {
            (PackedUserOperation memory uo,) = abi.decode(data[4:], (PackedUserOperation, bytes32));
            bytes4 selector;
            bytes memory callData = uo.callData;
            // Bytes arr representation: [bytes32(len), bytes4(executeUserOp.selector), bytes4(actualSelector),
            // bytes(actualCallData)]
            // 1. Copy actualSelector into a new var
            // 2. Shorten bytes arry by 8 by: store length - 8 into the new pointer location
            // 3. Move the callData pointer by 8
            assembly {
                selector := mload(add(callData, 36))

                let len := mload(callData)
                mstore(add(callData, 8), sub(len, 8))
                callData := add(callData, 8)
            }
            return (selector, callData);
        }
        return (bytes4(data[:4]), data[4:]);
    }
}
