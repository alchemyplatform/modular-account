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

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {FunctionReference} from "modular-account-libs/interfaces/IPluginManager.sol";
import {
    IPlugin,
    ManifestExecutionHook,
    ManifestAssociatedFunctionType,
    ManifestFunction,
    PluginManifest
} from "modular-account-libs/interfaces/IPlugin.sol";
import {ERC721PresetMinterPauserAutoId} from
    "@openzeppelin/contracts/token/ERC721/presets/ERC721PresetMinterPauserAutoId.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC777Recipient} from "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";
import {MockERC1155} from "../mocks/tokens/MockERC1155.sol";
import {MockERC777} from "../mocks/tokens/MockERC777.sol";

contract TokenReceiverTest is Test, IERC1155Receiver {
    UpgradeableModularAccount public acct;

    ERC721PresetMinterPauserAutoId public t0;
    MockERC777 public t1;
    MockERC1155 public t2;
    MockPlugin public mockPlugin;
    MultiOwnerModularAccountFactory public factory;
    MultiOwnerPlugin public multiOwnerPlugin;
    IEntryPoint public entryPoint;

    address public owner;
    address[] public owners;

    // init dynamic length arrays for use in args
    address[] public defaultOperators;
    uint256[] public tokenIds;
    uint256[] public tokenAmts;
    uint256[] public zeroTokenAmts;

    uint256 internal constant _TOKEN_AMOUNT = 1 ether;
    uint256 internal constant _TOKEN_ID = 0;
    uint256 internal constant _BATCH_TOKEN_IDS = 5;

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        multiOwnerPlugin = new MultiOwnerPlugin();
        factory = new MultiOwnerModularAccountFactory(
            address(this),
            address(multiOwnerPlugin),
            address(new UpgradeableModularAccount(entryPoint)),
            keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
            entryPoint
        );
        (owner,) = makeAddrAndKey("owner");
        owners = new address[](1);
        owners[0] = owner;
        acct = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));

        t0 = new ERC721PresetMinterPauserAutoId("t0", "t0", "");
        t0.mint(address(this));

        t1 = new MockERC777();
        t1.mint(address(this), _TOKEN_AMOUNT);

        t2 = new MockERC1155();
        t2.mint(address(this), _TOKEN_ID, _TOKEN_AMOUNT);
        for (uint256 i = 1; i < _BATCH_TOKEN_IDS; i++) {
            t2.mint(address(this), i, _TOKEN_AMOUNT);
            tokenIds.push(i);
            tokenAmts.push(_TOKEN_AMOUNT);
            zeroTokenAmts.push(0);
        }
    }

    function test_passERC721Transfer() public {
        assertEq(t0.ownerOf(_TOKEN_ID), address(this));
        t0.safeTransferFrom(address(this), address(acct), _TOKEN_ID);
        assertEq(t0.ownerOf(_TOKEN_ID), address(acct));
    }

    function test_passERC777Transfer() public {
        assertEq(t1.balanceOf(address(this)), _TOKEN_AMOUNT);
        assertEq(t1.balanceOf(address(acct)), 0);
        t1.transfer(address(acct), _TOKEN_AMOUNT);
        assertEq(t1.balanceOf(address(this)), 0);
        assertEq(t1.balanceOf(address(acct)), _TOKEN_AMOUNT);
    }

    function test_passERC1155Transfer() public {
        assertEq(t2.balanceOf(address(this), _TOKEN_ID), _TOKEN_AMOUNT);
        assertEq(t2.balanceOf(address(acct), _TOKEN_ID), 0);
        t2.safeTransferFrom(address(this), address(acct), _TOKEN_ID, _TOKEN_AMOUNT, "");
        assertEq(t2.balanceOf(address(this), _TOKEN_ID), 0);
        assertEq(t2.balanceOf(address(acct), _TOKEN_ID), _TOKEN_AMOUNT);

        for (uint256 i = 1; i < _BATCH_TOKEN_IDS; i++) {
            assertEq(t2.balanceOf(address(this), i), _TOKEN_AMOUNT);
            assertEq(t2.balanceOf(address(acct), i), 0);
        }
        t2.safeBatchTransferFrom(address(this), address(acct), tokenIds, tokenAmts, "");
        for (uint256 i = 1; i < _BATCH_TOKEN_IDS; i++) {
            assertEq(t2.balanceOf(address(this), i), 0);
            assertEq(t2.balanceOf(address(acct), i), _TOKEN_AMOUNT);
        }
    }

    function test_passIntrospection() public {
        bool isSupported;

        isSupported = acct.supportsInterface(type(IERC721Receiver).interfaceId);
        assertEq(isSupported, true);
        isSupported = acct.supportsInterface(type(IERC777Recipient).interfaceId);
        assertEq(isSupported, true);
        isSupported = acct.supportsInterface(type(IERC1155Receiver).interfaceId);
        assertEq(isSupported, true);
    }

    function test_hookOnERC721Transfer() public {
        uint8 preHookId = 1;
        uint8 postHookId = 2;
        _installHookOnSelector(IERC721Receiver.onERC721Received.selector, preHookId, postHookId);

        vm.expectCall(
            address(mockPlugin),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                preHookId,
                address(t0), // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(
                    IERC721Receiver.onERC721Received.selector, address(this), address(this), _TOKEN_ID, ""
                )
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin),
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector, postHookId, abi.encode(preHookId)),
            1
        );

        t0.safeTransferFrom(address(this), address(acct), _TOKEN_ID);
    }

    function test_hookOnERC777Transfer() public {
        uint8 preHookId = 1;
        uint8 postHookId = 2;
        _installHookOnSelector(IERC777Recipient.tokensReceived.selector, preHookId, postHookId);

        vm.expectCall(
            address(mockPlugin),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                preHookId,
                address(t1), // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(
                    IERC777Recipient.tokensReceived.selector,
                    address(this),
                    address(this),
                    address(acct),
                    _TOKEN_AMOUNT,
                    "",
                    ""
                )
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin),
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector, postHookId, abi.encode(preHookId)),
            1
        );

        t1.transfer(address(acct), _TOKEN_AMOUNT);
    }

    function test_hookOnERC1155Transfer() public {
        uint8 preHookId = 1;
        uint8 postHookId = 2;
        _installHookOnSelector(IERC1155Receiver.onERC1155Received.selector, preHookId, postHookId);

        vm.expectCall(
            address(mockPlugin),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                preHookId,
                address(t2), // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(
                    IERC1155Receiver.onERC1155Received.selector,
                    address(this),
                    address(this),
                    _TOKEN_ID,
                    _TOKEN_AMOUNT,
                    ""
                )
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin),
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector, postHookId, abi.encode(preHookId)),
            1
        );

        t2.safeTransferFrom(address(this), address(acct), _TOKEN_ID, _TOKEN_AMOUNT, "");
    }

    function test_hookOnERC1155BatchTransfer() public {
        uint8 preHookId = 1;
        uint8 postHookId = 2;
        _installHookOnSelector(IERC1155Receiver.onERC1155BatchReceived.selector, preHookId, postHookId);

        vm.expectCall(
            address(mockPlugin),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                preHookId,
                address(t2), // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(
                    IERC1155Receiver.onERC1155BatchReceived.selector,
                    address(this),
                    address(this),
                    tokenIds,
                    tokenAmts,
                    ""
                )
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin),
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector, postHookId, abi.encode(preHookId)),
            1
        );

        t2.safeBatchTransferFrom(address(this), address(acct), tokenIds, tokenAmts, "");
    }

    function _installHookOnSelector(bytes4 selector, uint8 preHookId, uint8 postHookId) internal {
        PluginManifest memory m;
        m.executionHooks = new ManifestExecutionHook[](1);
        m.executionHooks[0].executionSelector = selector;
        m.executionHooks[0].preExecHook = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: preHookId,
            dependencyIndex: 0
        });
        m.executionHooks[0].postExecHook = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: postHookId,
            dependencyIndex: 0
        });

        mockPlugin = new MockPlugin(m);

        vm.prank(owner);
        acct.installPlugin({
            plugin: address(mockPlugin),
            manifestHash: keccak256(abi.encode(m)),
            pluginInstallData: bytes(""),
            dependencies: new FunctionReference[](0)
        });
    }

    /**
     * NON-TEST FUNCTIONS - USED SO MINT DOESNT FAIL
     */
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4) external pure override returns (bool) {
        return false;
    }
}
