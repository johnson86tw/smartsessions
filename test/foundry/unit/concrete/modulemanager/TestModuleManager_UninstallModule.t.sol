// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../../utils/Imports.sol";
import "../../../utils/SmartAccountTestLab.t.sol";
import "../../shared/TestModuleManagement_Base.t.sol";


contract TestModuleManager_UninstallModule is Test, TestModuleManagement_Base {

    function setUp() public {
        setUpModuleManagement_Base();
    }

    function test_InstallModule_Success() public {
        assertFalse(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(mockValidator), ""),
            "Module should not be installed initially"
        );

        bytes memory callData = abi.encodeWithSelector(
            IModuleManager.installModule.selector, MODULE_TYPE_VALIDATOR, address(mockValidator), ""
        );

        // Preparing UserOperation for installing the module
        PackedUserOperation[] memory userOps =
            prepareExecutionUserOp(BOB, BOB_ACCOUNT, EXECTYPE_DEFAULT, address(BOB_ACCOUNT), 0, callData);

        ENTRYPOINT.handleOps(userOps, payable(address(BOB.addr)));

        assertTrue(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(mockValidator), ""),
            "Module should be installed"
        );
    }

    function test_UninstallModule_Success() public {
        // Setup: Install the module first
        bytes memory installCallData = abi.encodeWithSelector(
            IModuleManager.installModule.selector, MODULE_TYPE_VALIDATOR, address(mockValidator), ""
        );
        installModule(installCallData, MODULE_TYPE_VALIDATOR, address(mockValidator));
        
        assertTrue(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(VALIDATOR_MODULE), ""),
            "Module should not be installed initially"
        );
        assertTrue(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(mockValidator), ""),
            "Module should not be installed initially"
        );

        (address[] memory array, address next) = BOB_ACCOUNT.getValidatorsPaginated(address(0x1), 100);
        address remove = address(mockValidator);
        address prev = SentinelListHelper.findPrevious(array, remove);

        bytes memory callData = abi.encodeWithSelector(
            IModuleManager.uninstallModule.selector,
            MODULE_TYPE_VALIDATOR, // Todo: Test what if you pass MODULE_TYPE_EXECUTOR here
            address(mockValidator),
            // uninstallData needs to provide prev module address with data to uninstall
            abi.encode(prev, "")
        );

        PackedUserOperation[] memory userOps =
            prepareExecutionUserOp(BOB, BOB_ACCOUNT, EXECTYPE_DEFAULT, address(BOB_ACCOUNT), 0, callData);

        ENTRYPOINT.handleOps(userOps, payable(address(BOB.addr)));

        assertFalse(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(mockValidator), ""),
            "Module should not be installed anymore"
        );
        assertTrue(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(VALIDATOR_MODULE), ""),
            "Module should not be installed initially"
        );
    }

    function test_UninstallModule_NotInstalled() public {

        assertTrue(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(VALIDATOR_MODULE), ""),
            "Module should not be installed initially"
        );

        assertFalse(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(mockValidator), ""),
            "Module should not be installed"
        );

        (address[] memory array, address next) = BOB_ACCOUNT.getValidatorsPaginated(address(0x1), 100);
        address remove = address(mockValidator);
        address prev = SentinelListHelper.findPrevious(array, remove);

        bytes memory callData = abi.encodeWithSelector(
            IModuleManager.uninstallModule.selector,
            MODULE_TYPE_VALIDATOR,
            address(mockValidator),
            // uninstallData needs to provide prev module address with data to uninstall
            abi.encode(prev, "")
        );

        PackedUserOperation[] memory userOps =
            prepareExecutionUserOp(BOB, BOB_ACCOUNT, EXECTYPE_DEFAULT, address(BOB_ACCOUNT), 0, callData);

        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOps[0]);

        bytes memory expectedRevertReason = abi.encodeWithSignature(
            "ModuleNotInstalled(uint256,address)", MODULE_TYPE_VALIDATOR, address(mockValidator)
        );

        // Expect the UserOperationRevertReason event
        vm.expectEmit(true, true, true, true);

        emit UserOperationRevertReason(
            userOpHash, // userOpHash
            address(BOB_ACCOUNT), // sender
            userOps[0].nonce, // nonce
            expectedRevertReason
        );
        ENTRYPOINT.handleOps(userOps, payable(address(BOB.addr)));

        assertFalse(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(mockValidator), ""),
            "Module should not be installed"
        );
    }

    function test_UninstallModule_IncorrectPrevModuleData() public {
        // Setup: Install the module first
        test_InstallModule_Success(); // Use the test case directly for setup
        assertTrue(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(VALIDATOR_MODULE), ""),
            "Module should not be installed initially"
        );
        assertTrue(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(mockValidator), ""),
            "Module should not be installed initially"
        );

        (address[] memory array, address next) = BOB_ACCOUNT.getValidatorsPaginated(address(0x1), 100);
        address remove = address(mockValidator);

        bytes memory callData = abi.encodeWithSelector(
            IModuleManager.uninstallModule.selector, MODULE_TYPE_VALIDATOR, remove, abi.encode(address(0x66), "")
        );

        PackedUserOperation[] memory userOps =
            prepareExecutionUserOp(BOB, BOB_ACCOUNT, EXECTYPE_DEFAULT, address(BOB_ACCOUNT), 0, callData);

        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOps[0]);

        bytes memory expectedRevertReason = abi.encodeWithSignature("LinkedList_InvalidEntry(address)", remove);

        // Expect the UserOperationRevertReason event
        vm.expectEmit(true, true, true, true);

        emit UserOperationRevertReason(
            userOpHash, // userOpHash
            address(BOB_ACCOUNT), // sender
            userOps[0].nonce, // nonce
            expectedRevertReason
        );
        ENTRYPOINT.handleOps(userOps, payable(address(BOB.addr)));

        assertTrue(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(mockValidator), ""),
            "Module should not be installed"
        );
    }

    function test_UninstallLastValidator_Reverted() public {
        assertTrue(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(VALIDATOR_MODULE), ""),
            "Module should not be installed initially"
        );

        (address[] memory array, address next) = BOB_ACCOUNT.getValidatorsPaginated(address(0x1), 100);
        address remove = address(VALIDATOR_MODULE);
        address prev = SentinelListHelper.findPrevious(array, remove);

        bytes memory callData = abi.encodeWithSelector(
            IModuleManager.uninstallModule.selector, MODULE_TYPE_VALIDATOR, remove, abi.encode(prev, "")
        );

        PackedUserOperation[] memory userOps =
            prepareExecutionUserOp(BOB, BOB_ACCOUNT, EXECTYPE_DEFAULT, address(BOB_ACCOUNT), 0, callData);

        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOps[0]);

        bytes memory expectedRevertReason = abi.encodeWithSignature("CannotRemoveLastValidator()");

        // Expect the UserOperationRevertReason event
        vm.expectEmit(true, true, true, true);

        emit UserOperationRevertReason(
            userOpHash, // userOpHash
            address(BOB_ACCOUNT), // sender
            userOps[0].nonce, // nonce
            expectedRevertReason
        );
        ENTRYPOINT.handleOps(userOps, payable(BOB.addr));

        assertTrue(
            BOB_ACCOUNT.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(VALIDATOR_MODULE), ""),
            "Module should be installed"
        );
    }
}
