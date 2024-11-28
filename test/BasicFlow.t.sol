// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "./Base.t.sol";
import "contracts/ISmartSession.sol";
import { NoPolicy } from "./mock/NoPolicy.sol";

import "solmate/test/utils/mocks/MockERC20.sol";
import "forge-std/interfaces/IERC20.sol";
import "forge-std/console.sol";

contract BasicFlowTest is BaseTest {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;

    MockERC20 token;
    Account sessionSigner;

    function setUp() public virtual override {
        token = new MockERC20("MockToken", "MTK", 18);
        token.mint(instance.account, 100 ether);

        instance = makeAccountInstance("smartaccount");
        mockK1 = new MockK1Validator();

        IRegistry _registry = IRegistry(address(new MockRegistry()));
        vm.etch(address(registry), address(_registry).code);

        owner = makeAccount("owner");
        sessionSigner = makeAccount("sessionSigner");

        smartSession = new SmartSession();
        sudoPolicy = new SudoPolicy();
        simpleSessionValidator = new SimpleSessionValidator();

        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(mockK1),
            data: abi.encodePacked(owner.addr)
        });
    }

    function test_flow() public {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actionDatas = new ActionData[](1);
        actionDatas[0] = ActionData({
            actionTarget: address(token),
            actionTargetSelector: IERC20.transfer.selector,
            actionPolicies: policyDatas
        });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(simpleSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: abi.encodePacked(sessionSigner.addr),
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actionDatas,
            canUsePaymaster: true
        });

        PermissionId permissionId = smartSession.getPermissionId(session);
        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        bytes memory initData = abi.encodePacked(SmartSessionMode.UNSAFE_ENABLE, abi.encode(enableSessionsArray));

        vm.prank(owner.addr);
        instance.installModule({ moduleTypeId: MODULE_TYPE_VALIDATOR, module: address(smartSession), data: initData });

        // use the session by sessionSigner

        address recipient = makeAddr("recipient");

        UserOpData memory userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSigner.key, userOpData.userOpHash);

        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: permissionId, sig: abi.encodePacked(r, s, v) });

        userOpData.execUserOps();

        assertEq(token.balanceOf(recipient), 1 ether);
    }
}
