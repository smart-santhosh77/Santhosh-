// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FileRegistry {
    struct Proof {
        address reporter;
        uint64 timestamp;
    }

    mapping(bytes32 => Proof) public proofs;

    event FileHashRecorded(
        bytes32 indexed digest,
        string fileId,
        address indexed reporter,
        uint256 timestamp
    );

    function recordHash(bytes32 digest, string calldata fileId) external {
        require(digest != bytes32(0), "empty digest");
        require(bytes(fileId).length > 0 && bytes(fileId).length <= 64, "invalid file id");
        proofs[digest] = Proof(msg.sender, uint64(block.timestamp));
        emit FileHashRecorded(digest, fileId, msg.sender, block.timestamp);
    }
}
