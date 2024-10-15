// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// A dummy paymaster contract that attempts to withdraw a token during paymaster validation.
contract MockTokenPaymaster is IPaymaster {
    IERC20 public token;

    EntryPoint public entryPoint;

    constructor(IERC20 _token, EntryPoint _entryPoint) {
        token = _token;
        entryPoint = _entryPoint;
    }

    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32, uint256)
        external
        returns (bytes memory context, uint256 validationData)
    {
        // Attempt to withdraw a token
        SafeERC20.safeTransferFrom(token, userOp.sender, address(this), 10 ether);

        return ("", 0);
    }

    function postOp(PostOpMode, bytes calldata, uint256, uint256) external {}

    function deposit() external {
        entryPoint.depositTo{value: address(this).balance}(address(this));
    }
}
