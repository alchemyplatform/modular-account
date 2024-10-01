// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {Call} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {HookConfigLib} from "../../src/libraries/HookConfigLib.sol";
import {ModuleEntity, ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";
import {AllowlistModule} from "../../src/modules/permissions/AllowlistModule.sol";

import {Counter} from "../mocks/Counter.sol";
import {CustomValidationTestBase} from "../utils/CustomValidationTestBase.sol";

contract AllowlistModuleTest is CustomValidationTestBase {
    AllowlistModule public allowlistModule;

    AllowlistModule.AllowlistInit[] public allowlistInit;

    Counter[] public counters;

    uint32 public constant HOOK_ENTITY_ID = 0;

    event AllowlistTargetUpdated(
        uint32 indexed entityId,
        address indexed account,
        address indexed target,
        AllowlistModule.AllowlistEntry entry
    );
    event AllowlistSelectorUpdated(
        uint32 indexed entityId, address indexed account, bytes24 indexed targetAndSelector, bool allowed
    );

    function setUp() public {
        _signerValidation = ModuleEntityLib.pack(address(ecdsaValidationModule), TEST_DEFAULT_VALIDATION_ENTITY_ID);

        allowlistModule = new AllowlistModule();

        counters = new Counter[](10);

        for (uint256 i = 0; i < counters.length; i++) {
            counters[i] = new Counter();
        }

        // Don't call `_customValidationSetup` here, as we want to test various configurations of install data.
    }

    function testFuzz_allowlistHook_userOp_single(uint256 seed) public {
        AllowlistModule.AllowlistInit[] memory inits;
        (inits, seed) = _generateRandomizedAllowlistInit(seed);

        _copyInitToStorage(inits);
        _customValidationSetup();

        Call[] memory calls = new Call[](1);
        (calls[0], seed) = _generateRandomCall(seed);
        bytes memory expectedError = _getExpectedUserOpError(calls);

        _runExecUserOp(calls[0].target, calls[0].data, expectedError);
    }

    function testFuzz_allowlistHook_userOp_batch(uint256 seed) public {
        AllowlistModule.AllowlistInit[] memory inits;
        (inits, seed) = _generateRandomizedAllowlistInit(seed);

        _copyInitToStorage(inits);
        _customValidationSetup();

        Call[] memory calls;
        (calls, seed) = _generateRandomCalls(seed);
        bytes memory expectedError = _getExpectedUserOpError(calls);

        _runExecBatchUserOp(calls, expectedError);
    }

    function testFuzz_allowlistHook_runtime_single(uint256 seed) public {
        AllowlistModule.AllowlistInit[] memory inits;
        (inits, seed) = _generateRandomizedAllowlistInit(seed);

        _copyInitToStorage(inits);
        _customValidationSetup();

        Call[] memory calls = new Call[](1);
        (calls[0], seed) = _generateRandomCall(seed);
        bytes memory expectedError = _getExpectedRuntimeError(calls);

        if (keccak256(expectedError) == keccak256("emptyrevert")) {
            _runtimeExecExpFail(calls[0].target, calls[0].data, "");
        } else {
            _runtimeExec(calls[0].target, calls[0].data, expectedError);
        }
    }

    function testFuzz_allowlistHook_runtime_batch(uint256 seed) public {
        AllowlistModule.AllowlistInit[] memory inits;
        (inits, seed) = _generateRandomizedAllowlistInit(seed);

        _copyInitToStorage(inits);
        _customValidationSetup();

        Call[] memory calls;
        (calls, seed) = _generateRandomCalls(seed);
        bytes memory expectedError = _getExpectedRuntimeError(calls);

        if (keccak256(expectedError) == keccak256("emptyrevert")) {
            _runtimeExecBatchExpFail(calls, "");
        } else {
            _runtimeExecBatch(calls, expectedError);
        }
    }

    function _beforeInstallStep(address accountImpl) internal override {
        // Expect events to be emitted from onInstall
        for (uint256 i = 0; i < allowlistInit.length; i++) {
            vm.expectEmit(address(allowlistModule));
            emit AllowlistTargetUpdated(
                HOOK_ENTITY_ID,
                accountImpl,
                allowlistInit[i].target,
                AllowlistModule.AllowlistEntry({
                    allowed: true,
                    hasSelectorAllowlist: allowlistInit[i].hasSelectorAllowlist
                })
            );

            if (!allowlistInit[i].hasSelectorAllowlist) {
                continue;
            }

            for (uint256 j = 0; j < allowlistInit[i].selectors.length; j++) {
                bytes24 targetAndSelector = bytes24(
                    bytes24(bytes20(allowlistInit[i].target)) | (bytes24(allowlistInit[i].selectors[j]) >> 160)
                );
                vm.expectEmit(address(allowlistModule));
                emit AllowlistSelectorUpdated(HOOK_ENTITY_ID, accountImpl, targetAndSelector, true);
            }
        }
    }

    function _generateRandomCalls(uint256 seed) internal view returns (Call[] memory, uint256) {
        uint256 length = seed % 10;
        seed = _next(seed);

        Call[] memory calls = new Call[](length);

        for (uint256 i = 0; i < length; i++) {
            (calls[i], seed) = _generateRandomCall(seed);
        }

        return (calls, seed);
    }

    function _generateRandomCall(uint256 seed) internal view returns (Call memory call, uint256 newSeed) {
        // Half of the time, the target is a random counter, the other half, it's a random address.
        bool isCounter = seed % 2 == 0;
        seed = _next(seed);

        call.target = isCounter ? address(counters[seed % counters.length]) : address(uint160(uint256(seed)));
        seed = _next(seed);

        bool validSelector = seed % 2 == 0;
        seed = _next(seed);

        if (validSelector) {
            uint256 selectorIndex = seed % 3;
            seed = _next(seed);

            if (selectorIndex == 0) {
                call.data = abi.encodeCall(Counter.setNumber, (seed % 100));
            } else if (selectorIndex == 1) {
                call.data = abi.encodeCall(Counter.increment, ());
            } else {
                call.data = abi.encodeWithSignature("number()");
            }

            seed = _next(seed);
        } else {
            call.data = abi.encodePacked(bytes4(uint32(uint256(seed))));
            seed = _next(seed);
        }

        return (call, seed);
    }

    function _getExpectedUserOpError(Call[] memory calls) internal view returns (bytes memory) {
        for (uint256 i = 0; i < calls.length; i++) {
            Call memory call = calls[i];

            (bool allowed, bool hasSelectorAllowlist) =
                allowlistModule.targetAllowlist(HOOK_ENTITY_ID, call.target, address(account1));
            if (allowed) {
                if (
                    hasSelectorAllowlist
                        && !allowlistModule.selectorAllowlist(
                            HOOK_ENTITY_ID, call.target, bytes4(call.data), address(account1)
                        )
                ) {
                    return abi.encodeWithSelector(
                        IEntryPoint.FailedOpWithRevert.selector,
                        0,
                        "AA23 reverted",
                        abi.encodeWithSelector(AllowlistModule.SelectorNotAllowed.selector)
                    );
                }
            } else {
                return abi.encodeWithSelector(
                    IEntryPoint.FailedOpWithRevert.selector,
                    0,
                    "AA23 reverted",
                    abi.encodeWithSelector(AllowlistModule.TargetNotAllowed.selector)
                );
            }
        }

        return "";
    }

    function _getExpectedRuntimeError(Call[] memory calls) internal view returns (bytes memory) {
        for (uint256 i = 0; i < calls.length; i++) {
            Call memory call = calls[i];

            (bool allowed, bool hasSelectorAllowlist) =
                allowlistModule.targetAllowlist(HOOK_ENTITY_ID, call.target, address(account1));
            if (allowed) {
                if (
                    hasSelectorAllowlist
                        && !allowlistModule.selectorAllowlist(
                            HOOK_ENTITY_ID, call.target, bytes4(call.data), address(account1)
                        )
                ) {
                    return abi.encodeWithSelector(
                        ModularAccountBase.PreRuntimeValidationHookFailed.selector,
                        address(allowlistModule),
                        HOOK_ENTITY_ID,
                        abi.encodeWithSelector(AllowlistModule.SelectorNotAllowed.selector)
                    );
                }
            } else {
                return abi.encodeWithSelector(
                    ModularAccountBase.PreRuntimeValidationHookFailed.selector,
                    address(allowlistModule),
                    HOOK_ENTITY_ID,
                    abi.encodeWithSelector(AllowlistModule.TargetNotAllowed.selector)
                );
            }
        }

        // At this point, we have returned any error that would come from the AllowlistModule.
        // But, because this is in the runtime path, the Counter itself may throw if it is not a valid selector.

        for (uint256 i = 0; i < calls.length; i++) {
            Call memory call = calls[i];
            bytes4 selector = bytes4(call.data);

            if (
                selector != Counter.setNumber.selector && selector != Counter.increment.selector
                    && selector != bytes4(abi.encodeWithSignature("number()"))
            ) {
                //todo: better define a way to handle empty reverts.
                return "emptyrevert";
            }
        }

        return "";
    }

    function _generateRandomizedAllowlistInit(uint256 seed)
        internal
        view
        returns (AllowlistModule.AllowlistInit[] memory, uint256)
    {
        uint256 length = seed % 10;
        seed = _next(seed);

        AllowlistModule.AllowlistInit[] memory init = new AllowlistModule.AllowlistInit[](length);

        for (uint256 i = 0; i < length; i++) {
            // Half the time, the target is a random counter, the other half, it's a random address.
            bool isCounter = seed % 2 == 0;
            seed = _next(seed);

            address target =
                isCounter ? address(counters[seed % counters.length]) : address(uint160(uint256(seed)));

            bool hasSelectorAllowlist = seed % 2 == 0;
            seed = _next(seed);

            uint256 selectorLength = seed % 10;
            seed = _next(seed);

            bytes4[] memory selectors = new bytes4[](selectorLength);

            for (uint256 j = 0; j < selectorLength; j++) {
                // half of the time, the selector is a valid selector on counter, the other half it's a random
                // selector

                bool isCounterSelector = seed % 2 == 0;
                seed = _next(seed);

                if (isCounterSelector) {
                    uint256 selectorIndex = seed % 3;
                    seed = _next(seed);

                    if (selectorIndex == 0) {
                        selectors[j] = Counter.setNumber.selector;
                    } else if (selectorIndex == 1) {
                        selectors[j] = Counter.increment.selector;
                    } else {
                        selectors[j] = bytes4(abi.encodeWithSignature("number()"));
                    }
                } else {
                    selectors[j] = bytes4(uint32(uint256(seed)));
                    seed = _next(seed);
                }

                selectors[j] = bytes4(uint32(uint256(keccak256(abi.encodePacked(seed, j)))));
                seed = _next(seed);
            }

            init[i] = AllowlistModule.AllowlistInit(target, hasSelectorAllowlist, selectors);
        }

        return (init, seed);
    }

    function _next(uint256 seed) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(seed)));
    }

    function _initialValidationConfig()
        internal
        virtual
        override
        returns (ModuleEntity, bool, bool, bool, bytes4[] memory, bytes memory, bytes[] memory)
    {
        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook(address(allowlistModule), HOOK_ENTITY_ID),
            abi.encode(HOOK_ENTITY_ID, allowlistInit)
        );
        // patched to also work during SMA tests by differentiating the validation
        _signerValidation = ModuleEntityLib.pack(address(ecdsaValidationModule), type(uint32).max - 1);
        return
            (_signerValidation, true, true, true, new bytes4[](0), abi.encode(type(uint32).max - 1, owner1), hooks);
    }

    // Unfortunately, this is a feature that solidity has only implemented in via-ir, so we need to do it manually
    // to be able to run the tests in lite mode.
    function _copyInitToStorage(AllowlistModule.AllowlistInit[] memory init) internal {
        for (uint256 i = 0; i < init.length; i++) {
            allowlistInit.push(init[i]);
        }
    }
}
