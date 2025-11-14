// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {console} from "forge-std/console.sol";

import {SemiModularAccountBytecode} from "../../src/account/SemiModularAccountBytecode.sol";

import {IFiatToken_v2_2} from "../sample/IFiatToken_v2_2.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

// A technical demonstration of using USDC's transferWithAuthorization function
// via a Modular Account. This pattern can be used to interact with any token
// contract that supports EIP-3009 (TransferWithAuthorization), if they support smart wallets via
// ERC-1271 signatures / ERC-7598 extension to EIP-3009.
contract TransferWithAuthorizationTest is AccountTestBase {
    address public USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    // keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256
    // validBefore,bytes32 nonce)")
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

    // keccak256("ReplaySafeHash(bytes32 hash)")
    bytes32 public constant REPLAY_SAFE_HASH_TYPEHASH =
        0x294a8735843d4afb4f017c76faf3b7731def145ed0025fc9b1d5ce30adf113ff;

    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
    bytes32 public constant ACCOUNT_DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    address public ownerAddr;
    uint256 public ownerPrivKey;
    SemiModularAccountBytecode public userAccount;
    address public recipient;

    uint256 transferAmount = 250e6; // 250 USDC (6 decimals)

    function setUp() public override {
        (ownerAddr, ownerPrivKey) = makeAddrAndKey("owner");

        recipient = makeAddr("recipient");

        // Create account to use
        userAccount = factory.createSemiModularAccount({owner: ownerAddr, salt: 0});
    }

    // Run this test with:
    // forge test --mt test_useUSDCTransferWithAuthorization -vvvv --fork-url $BASE_MAINNET_RPC_URL
    function test_useUSDCTransferWithAuthorization() public {
        // We will first mock a call from the USDC admin to mint some tokens for userAccount
        address mockMinter = makeAddr("minter");
        address masterMinter = IFiatToken_v2_2(USDC).masterMinter();

        vm.prank(masterMinter);
        IFiatToken_v2_2(USDC).configureMinter(mockMinter, type(uint256).max);

        uint256 mintAmount = 1000e6; // 1000 USDC (6 decimals)
        vm.prank(mockMinter);
        IFiatToken_v2_2(USDC).mint(address(userAccount), mintAmount);

        // Now, we want to use transferWithAuthorization to move some USDC from accuserAccountunt1 to another
        // address

        // Prepare the parameters for transferWithAuthorization

        uint256 validAfter = block.timestamp; // valid immediately
        uint256 validBefore = block.timestamp + 1 hours; // valid for the next hour
        bytes32 nonce = keccak256(abi.encodePacked("unique-nonce-123"));
        bytes32 structHash = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                address(userAccount),
                recipient,
                transferAmount,
                validAfter,
                validBefore,
                nonce
            )
        );

        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", IFiatToken_v2_2(USDC).DOMAIN_SEPARATOR(), structHash));

        // We now have the EIP-712 digest, which is what the USDC token will compute and expect to be used.
        // However, the account will actually need to sign the `ReplaySafeHash` of this digest.

        bytes32 replaySafeStructHash = keccak256(abi.encode(REPLAY_SAFE_HASH_TYPEHASH, digest));

        bytes32 accountDomainSeparator =
            keccak256(abi.encode(ACCOUNT_DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(userAccount)));

        bytes32 replaySafeDigest =
            keccak256(abi.encodePacked("\x19\x01", accountDomainSeparator, replaySafeStructHash));

        // Sign the replaySafeDigest with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivKey, replaySafeDigest);

        // Now, we have to pack the v,r,s signature into an ERC-1271 signature.
        // Normally handled by the SDK, but here's how to do it manually:
        // 1 byte validation option: 0x01 for Global Validation (defaiult)
        // 4 bytes validation entity ID: 0x00000000 for SMA owner, other values for session keys / secondary
        // owners. 1 byte signature segment marker: 0xFF. Used to distinguish between permission hook data and
        // signature data.
        // 1 byte signature type: 0x00 for ECDSA, 0x01 for nested contract signature
        // Then the actual 65-byte ECDSA signature (r,s,v)
        bytes memory signature = abi.encodePacked(hex"01", hex"00000000", hex"FF", hex"00", r, s, v);

        // USDC checks block timestamp with `<` and `>`, so we need to make sure the current block time is within
        // the valid range
        uint256 currentTime = block.timestamp;
        vm.warp(block.timestamp + 5 minutes);

        // Finally, we can call transferWithAuthorization on the USDC contract via the recipient account
        vm.prank(recipient);
        IFiatToken_v2_2(USDC)
            .transferWithAuthorization({
                from: address(userAccount),
                to: recipient,
                value: transferAmount,
                validAfter: currentTime,
                validBefore: currentTime + 1 hours,
                nonce: keccak256(abi.encodePacked("unique-nonce-123")),
                signature: signature
            });

        // Verify balance change
        uint256 recipientBalance = IFiatToken_v2_2(USDC).balanceOf(recipient);
        assertEq(recipientBalance, transferAmount);
    }
}
