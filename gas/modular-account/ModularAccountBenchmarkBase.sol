// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ValidationDataView} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {SemiModularAccountBytecode} from "../../src/account/SemiModularAccountBytecode.sol";
import {AccountFactory} from "../../src/factory/AccountFactory.sol";
import {FALLBACK_VALIDATION} from "../../src/helpers/Constants.sol";
import {HookConfig, HookConfigLib} from "../../src/libraries/HookConfigLib.sol";
import {ModuleEntity, ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";
import {ValidationConfig, ValidationConfigLib} from "../../src/libraries/ValidationConfigLib.sol";
import {AllowlistModule} from "../../src/modules/permissions/AllowlistModule.sol";
import {ERC20TokenLimitModule} from "../../src/modules/permissions/ERC20TokenLimitModule.sol";
import {TimeRangeAndPaymasterGuardModule} from "../../src/modules/permissions/TimeRangeAndPaymasterGuardModule.sol";
import {ECDSAValidationModule} from "../../src/modules/validation/ECDSAValidationModule.sol";

import {Counter} from "../../test/mocks/Counter.sol";
import {ModuleSignatureUtils} from "../../test/utils/ModuleSignatureUtils.sol";
import {BenchmarkBase} from "../BenchmarkBase.sol";

abstract contract ModularAccountBenchmarkBase is BenchmarkBase, ModuleSignatureUtils {
    using ValidationConfigLib for ValidationConfig;

    AccountFactory public factory;
    ModularAccount public accountImpl;
    SemiModularAccountBytecode public semiModularImpl;
    ECDSAValidationModule public ecdsaValidationModule;

    AllowlistModule public allowlistModule;
    TimeRangeAndPaymasterGuardModule public timeRangeAndPaymasterGuardModule;
    ERC20TokenLimitModule public erc20SpendLimitModule;

    ModularAccount public account1;
    ModuleEntity public signerValidation;

    address public sessionSigner1;
    uint256 public sessionSigner1Key;

    Counter public counter;

    constructor(string memory accountImplName) BenchmarkBase(accountImplName) {
        (sessionSigner1, sessionSigner1Key) = makeAddrAndKey("session1");

        accountImpl = _deployModularAccount(IEntryPoint(entryPoint));
        semiModularImpl = _deploySemiModularAccountBytecode(IEntryPoint(entryPoint));
        ecdsaValidationModule = _deployECDSAValidationModule();

        factory = new AccountFactory(
            entryPoint, accountImpl, semiModularImpl, address(ecdsaValidationModule), address(this)
        );

        allowlistModule = new AllowlistModule();
        timeRangeAndPaymasterGuardModule = new TimeRangeAndPaymasterGuardModule();
        erc20SpendLimitModule = new ERC20TokenLimitModule();

        counter = new Counter();
        counter.increment();
    }

    function _deployAccount1() internal {
        account1 = factory.createAccount(owner1, 0, 0);
        signerValidation = ModuleEntityLib.pack(address(ecdsaValidationModule), 0);
    }

    function _deploySemiModularAccountBytecode1() internal {
        account1 = ModularAccount(payable(factory.createSemiModularAccount(owner1, 0)));
        signerValidation = FALLBACK_VALIDATION;
    }

    // Session key case 1:
    // - Uses SingleSignerValidation
    // - Only applies to `execute`, `executeBatch`, not global.
    // - Has hooks for:
    //   - Allowlist: only allows a counter and the mock ERC-20
    //   - Time range: only allows within a certain time range
    //   - ERC-20 spend limit: caps the amount of MockERC20 that can be spent
    function _getInstallDataSessionKeyCase1() internal view returns (bytes memory) {
        uint32 sessionKeyEntityId = 1;

        ValidationConfig validationConfig = ValidationConfigLib.pack({
            _module: address(ecdsaValidationModule),
            _entityId: sessionKeyEntityId,
            _isGlobal: false,
            _isSignatureValidation: false,
            _isUserOpValidation: true
        });

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = ModularAccountBase.execute.selector;
        selectors[1] = ModularAccountBase.executeBatch.selector;

        bytes memory installData = abi.encode(sessionKeyEntityId, sessionSigner1);

        bytes[] memory hooks = new bytes[](3);

        // Allowlist init data
        AllowlistModule.AllowlistInput[] memory allowlistInput = new AllowlistModule.AllowlistInput[](2);
        allowlistInput[0] = AllowlistModule.AllowlistInput({
            target: address(counter),
            hasSelectorAllowlist: false,
            selectors: new bytes4[](0)
        });

        bytes4[] memory tokenSelectors = new bytes4[](1);
        tokenSelectors[0] = IERC20.transfer.selector;

        allowlistInput[1] = AllowlistModule.AllowlistInput({
            target: address(mockErc20),
            hasSelectorAllowlist: true,
            selectors: tokenSelectors
        });

        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook({_module: address(allowlistModule), _entityId: 0}),
            abi.encode(uint32(0), allowlistInput)
        );

        // Time range hook
        hooks[1] = abi.encodePacked(
            HookConfigLib.packValidationHook({_module: address(timeRangeAndPaymasterGuardModule), _entityId: 0}),
            abi.encode(uint32(0), 1000, 100, address(0))
        );

        // ERC-20 spend limit hook
        ERC20TokenLimitModule.ERC20SpendLimit[] memory spendLimits = new ERC20TokenLimitModule.ERC20SpendLimit[](1);
        spendLimits[0] = ERC20TokenLimitModule.ERC20SpendLimit({token: address(mockErc20), limit: 100 ether});

        hooks[2] = abi.encodePacked(
            HookConfigLib.packExecHook({
                _module: address(erc20SpendLimitModule),
                _entityId: 0,
                _hasPre: true,
                _hasPost: false
            }),
            abi.encode(uint32(0), spendLimits)
        );

        return
            abi.encodeCall(ModularAccountBase.installValidation, (validationConfig, selectors, installData, hooks));
    }

    function _installSessionKey_case1() internal returns (ModuleEntity sessionKeyValidation) {
        vm.prank(address(entryPoint));
        (bool success,) = address(account1).call(_getInstallDataSessionKeyCase1());
        require(success, "Install Session key 1 failed");

        return ModuleEntityLib.pack(address(ecdsaValidationModule), 1);
    }

    function _verifySessionKeyCase1InstallState() internal view {
        // Assert account state is correctly set up

        ValidationDataView memory validationData =
            account1.getValidationData(ModuleEntityLib.pack(address(ecdsaValidationModule), 1));

        // Flags
        assertFalse(validationData.isGlobal);
        assertFalse(validationData.isSignatureValidation);
        assertTrue(validationData.isUserOpValidation);

        // Validation hooks
        assertEq(validationData.validationHooks.length, 2);
        assertEq(
            HookConfig.unwrap(validationData.validationHooks[0]),
            HookConfig.unwrap(HookConfigLib.packValidationHook(address(allowlistModule), 0))
        );
        assertEq(
            HookConfig.unwrap(validationData.validationHooks[1]),
            HookConfig.unwrap(HookConfigLib.packValidationHook(address(timeRangeAndPaymasterGuardModule), 0))
        );

        // Execution hooks
        assertEq(validationData.executionHooks.length, 1);
        assertEq(
            HookConfig.unwrap(validationData.executionHooks[0]),
            HookConfig.unwrap(
                HookConfigLib.packExecHook({
                    _module: address(erc20SpendLimitModule),
                    _entityId: 0,
                    _hasPre: true,
                    _hasPost: false
                })
            )
        );

        // Selectors
        assertEq(validationData.selectors.length, 2);
        assertEq(validationData.selectors[0], ModularAccountBase.execute.selector);
        assertEq(validationData.selectors[1], ModularAccountBase.executeBatch.selector);

        // Assert hooks state is correctly set up

        // Allowlist
        (bool counterAllowed, bool counterHasSelectorList) =
            allowlistModule.addressAllowlist(0, address(counter), address(account1));
        assertTrue(counterAllowed);
        assertFalse(counterHasSelectorList);

        (bool erc20Allowed, bool erc20HasSelectorList) =
            allowlistModule.addressAllowlist(0, address(mockErc20), address(account1));
        assertTrue(erc20Allowed);
        assertTrue(erc20HasSelectorList);

        bool erc20TransferSelectorAllowed =
            allowlistModule.selectorAllowlist(0, IERC20.transfer.selector, address(mockErc20), address(account1));
        assertTrue(erc20TransferSelectorAllowed);

        // Time range
        (uint48 validUntil, uint48 validAfter,) =
            timeRangeAndPaymasterGuardModule.timeRangeAndPaymasterGuards(0, address(account1));
        assertEq(validUntil, 1000);
        assertEq(validAfter, 100);

        // ERC-20 spend limit
        (bool hasLimit, uint256 limit) = erc20SpendLimitModule.limits(0, address(mockErc20), address(account1));
        assertTrue(hasLimit);
        assertEq(limit, 100 ether);
    }
}
