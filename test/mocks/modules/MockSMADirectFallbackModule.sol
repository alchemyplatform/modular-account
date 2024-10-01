// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

import {SemiModularAccountBase} from "../../../src/account/SemiModularAccountBase.sol";
import {BaseModule} from "../../../src/modules/BaseModule.sol";

contract MockSMADirectFallbackModule is BaseModule, IExecutionHookModule, IValidationHookModule {
    bool public preHookRan = false;
    bool public postHookRan = false;
    bool public validationHookRan = false;

    function preRuntimeValidationHook(uint32, address, uint256, bytes calldata, bytes calldata) external {
        validationHookRan = true;
    }

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {
        preHookRan = false;
        postHookRan = false;
        validationHookRan = false;
    }

    function moduleId() external pure override returns (string memory) {
        return "erc6900.direct-call-module.1.0.0";
    }

    // function

    function preExecutionHook(uint32, address sender, uint256, bytes calldata)
        external
        override
        returns (bytes memory)
    {
        address fallbackSigner = SemiModularAccountBase(payable(msg.sender)).getFallbackSigner();
        require(sender == fallbackSigner, "mock SMA fallback direct call call pre execution hook failed");
        preHookRan = true;
        return abi.encode(keccak256(hex"04546b"));
    }

    function postExecutionHook(uint32, bytes calldata preExecHookData) external override {
        require(
            abi.decode(preExecHookData, (bytes32)) == keccak256(hex"04546b"),
            "mock direct call post execution hook failed"
        );
        postHookRan = true;
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(BaseModule, IERC165)
        returns (bool)
    {
        return interfaceId == type(IExecutionHookModule).interfaceId
            || interfaceId == type(IValidationHookModule).interfaceId || super.supportsInterface(interfaceId);
    }

    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        override
        returns (uint256)
    {}

    function preSignatureValidationHook(uint32 entityId, address sender, bytes32 hash, bytes calldata signature)
        external
        view
        override
    {}
}
