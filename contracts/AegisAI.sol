// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AegisAI {
    struct Threat {
        bytes32 hash;
        string threatType;
        uint8 confidence;
        address reporter;
        uint40 timestamp;
    }

    Threat[] public threats;
    mapping(address => uint256) public reputation;
    mapping(bytes32 => bool) public seen;

    event ThreatReported(
        bytes32 indexed hash,
        string threatType,
        uint8 confidence,
        address indexed reporter
    );

    modifier nonDuplicate(bytes32 hash) {
        require(!seen[hash], "Duplicate");
        _;
    }

    function reportThreat(
        bytes32 _hash,
        string calldata _type,
        uint8 _confidence
    ) external nonDuplicate(_hash) {
        require(_confidence >= 50 && _confidence <= 100, "Invalid confidence");
        threats.push(Threat(_hash, _type, _confidence, msg.sender, uint40(block.timestamp)));
        reputation[msg.sender] += 15;
        seen[_hash] = true;
        emit ThreatReported(_hash, _type, _confidence, msg.sender);
    }

    function getThreatCount() external view returns (uint256) {
        return threats.length;
    }
}