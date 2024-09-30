// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

library ExecutionLib {
    /// @param target The address of the contract to call.
    /// @param value The value to send with the call.
    /// @param data The call data.
    /// @return result The return data of the call, or the error message from the call if call reverts.
    function exec(address target, uint256 value, bytes memory data) internal returns (bytes memory result) {
        // Manually call, collecting return data.
        assembly ("memory-safe") {
            let success := call(gas(), target, value, add(data, 0x20), mload(data), codesize(), 0)

            // Allocate space for the return data, advancing the memory pointer to the nearest word
            result := mload(0x40)
            mstore(0x40, and(add(add(result, returndatasize()), 0x3f), not(0x1f)))

            // Copy the returned data to the allocated space.
            mstore(result, returndatasize())
            returndatacopy(add(result, 0x20), 0, returndatasize())

            // Revert if the call was not successful.
            if iszero(success) { revert(add(result, 0x20), returndatasize()) }
        }
    }

    // Call the following function to address(this), without capturing any return data.
    // If the call reverts, the revert message will be directly bubbled up.
    function callSelfBubbleOnRevert(bytes memory callData) internal {
        // Manually call, without collecting return data unless there's a revert.
        assembly ("memory-safe") {
            let success :=
                call(
                    gas(),
                    address(),
                    /*value*/
                    0,
                    /*argOffset*/
                    add(callData, 0x20),
                    /*argSize*/
                    mload(callData),
                    /*retOffset*/
                    codesize(),
                    /*retSize*/
                    0
                )

            // directly bubble up revert messages, if any.
            if iszero(success) {
                // For memory safety, copy this revert data to scratch space past the end of used memory. Because
                // we immediately revert, we can omit storing the length as we normally would for a `bytes memory`
                // type, as well as omit finalizing the allocation by updating the free memory pointer.
                let revertDataLocation := mload(0x40)
                returndatacopy(revertDataLocation, 0, returndatasize())
                revert(revertDataLocation, returndatasize())
            }
        }
    }

    // Manually collect and store the return data from the most recent external call into a `bytes memory`.
    function collectReturnData() internal pure returns (bytes memory returnData) {
        assembly ("memory-safe") {
            // Allocate a buffer of that size, advancing the memory pointer to the nearest word
            returnData := mload(0x40)
            mstore(returnData, returndatasize())
            mstore(0x40, and(add(add(returnData, returndatasize()), 0x3f), not(0x1f)))

            // Copy over the return data
            returndatacopy(add(returnData, 0x20), 0, returndatasize())
        }
    }
}
