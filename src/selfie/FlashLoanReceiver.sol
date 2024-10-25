// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import {SelfiePool} from "./SelfiePool.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {DamnValuableVotes} from "../DamnValuableVotes.sol";
import {SimpleGovernance} from "./SimpleGovernance.sol";

contract FlashLoanReceiver is IERC3156FlashBorrower {
    SelfiePool private pool;
    DamnValuableVotes private DVT;
    SimpleGovernance private governance;

    constructor(SelfiePool _pool, DamnValuableVotes _token, SimpleGovernance _governance) {
        pool = _pool;
        DVT = _token;
        governance = _governance;
    }

    function onFlashLoan(address, address token, uint256 amount, uint256 fee, bytes calldata data)
        external
        returns (bytes32)
    {
        DVT.delegate(address(this));
        governance.queueAction(address(pool), 0, data);
        DVT.approve(address(pool), amount);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    function _executeActionDuringFlashLoan() internal {}
}
