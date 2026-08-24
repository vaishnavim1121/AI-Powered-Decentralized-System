// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ThreatIntelligence {
    struct Threat {
        string threatHash;
        address reporter;
        uint256 timestamp;
        uint8 severity;
        bool validated;
    }

    Threat[] public threats;

    event ThreatSubmitted(uint256 id, string threatHash, address reporter);

    function submitThreat(string memory _threatHash, uint8 _severity) public {
        threats.push(Threat(_threatHash, msg.sender, block.timestamp, _severity, false));
        emit ThreatSubmitted(threats.length - 1, _threatHash, msg.sender);
    }

    function validateThreat(uint256 _id) public {
        threats[_id].validated = true;
    }

    function getThreat(uint256 _id) public view returns (string memory, address, uint256, uint8, bool) {
        Threat memory t = threats[_id];
        return (t.threatHash, t.reporter, t.timestamp, t.severity, t.validated);
    }

    function getCount() public view returns (uint256) {
        return threats.length;
    }
}