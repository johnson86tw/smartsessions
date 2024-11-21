// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

///////  Custom EIP712 types  ////
//  to keep the documentation of nested EIP712 hashes readable, we trunkated the EIP712 definitions of nested structs.
// If you want to reproduce the hashes, you can use the following alloy helper tool:
// https://github.com/erc7579/smartsessions/blob/main/rust/main.rs

// PolicyData(address policy,bytes initData)
bytes32 constant POLICY_DATA_TYPEHASH = 0xdddac12cd8b10a071bea04226e97ac9490698394e19224abc47a5cfeeeb6ee97;

// ActionData(bytes4 actionTargetSelector,address actionTarget,PolicyData[] actionPolicies)
bytes32 constant ACTION_DATA_TYPEHASH = 0x35809859dccf8877c407a59527c2f00fb81ca9c198ebcb0c832c3deaa38d3502;

// ERC7739Context(bytes32 appDomainSeparator,string[] contentName)
bytes32 constant ERC7739_CONTEXT_TYPEHASH = 0x006166b2b3a1edaf1da1ce02715d02d4979a4ab93755bff9ec054b0e6a96a1da;

// ERC7739Data(ERC7739Context[] allowedERC7739Content,PolicyData[] erc1271Policies)
bytes32 constant ERC7739_DATA_TYPEHASH = 0xdfd9b5718eebaa2484740b4ea6939e96189024c15848f16ccce901118114e152;

// SignedSession(
//      address account,
//      address smartSession,
//      uint8 mode,
//      address sessionValidator,
//      bytes32 salt,
//      bytes sessionValidatorInitData,
//      PolicyData[] userOpPolicies,
//      ERC7739Data erc7739Policies,
//      ActionData[] actions,
//      uint256 nonce)
bytes32 constant SESSION_TYPEHASH = 0xc1211ac69ffe18c099e596ce9a4395ae7a1400e7db4ae9a45fcdc0a67709ffa2;

// ChainSession(uint64 chainId,Session session)
bytes32 constant CHAIN_SESSION_TYPEHASH = 0xce180a7804b7aa8318434f77c9fa28e064a722408ea7b7874d9163732f3ba1d5;

// MultiChainSession(ChainSession[] sessionsAndChainIds)
bytes32 constant MULTICHAIN_SESSION_TYPEHASH = 0xb8891a1d91e981333b5a0f2583fadff6cb80006149b9f8407608eb4c0a130c7d;

//0xb03948446334eb9b2196d5eb166f69b9d49403eb4a12f36de8d3f9f3cb8e15c3
bytes32 constant _MULTICHAIN_DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version)");

// One should use the domain separator below where possible
// or provide the following EIP712Domain struct to the signTypedData() function
// { Name: "SmartSession" (string),
//   Version: "1" (string) }
// Name and version are consistent with what is returned by _domainNameAndVersion()
// Empty fields: version, chainId, verifyingContract are omitted as per EIP-712
// it is introduced for compatibility with signTypedData()
// all the critical data such as chainId and verifyingContract is included
// in session hashes, so here the mock data compatible accross chains is used
// see https://docs.metamask.io/wallet/reference/eth_signtypeddata_v4 for details

// 0x057501e891776d1482927e5f094ae44049a4d893ba2d7b334dd7db8d38d3a0e1
bytes32 constant _MULTICHAIN_DOMAIN_SEPARATOR =
    keccak256(abi.encode(_MULTICHAIN_DOMAIN_TYPEHASH, keccak256("SmartSession"), keccak256("1")));

library HashLib {
    error ChainIdMismatch(uint64 providedChainId);
    error HashMismatch(bytes32 providedHash, bytes32 computedHash);

    using EfficientHashLib for bytes32;
    using HashLib for *;
    using EfficientHashLib for *;

    /**
     * Mimics SignTypedData() behavior
     * 1. hashStruct(Session)
     * 2. hashStruct(ChainSession)
     * 3. abi.encodePacked hashStruct's for 2) together
     * 4. Hash it together with MULTI_CHAIN_SESSION_TYPEHASH
     * as it was MultiChainSession struct
     * 5. Add multichain domain separator
     * This method doest same, just w/o 1. as it is already provided to us as a digest
     */
    function multichainDigest(ChainDigest[] memory hashesAndChainIds) internal pure returns (bytes32) {
        bytes32 structHash =
            keccak256(abi.encode(MULTICHAIN_SESSION_TYPEHASH, hashesAndChainIds.hashChainDigestArray()));

        return MessageHashUtils.toTypedDataHash(_MULTICHAIN_DOMAIN_SEPARATOR, structHash);
    }

    /**
     * Hash array of ChainDigest structs
     */
    function hashChainDigestArray(ChainDigest[] memory chainDigestArray) internal pure returns (bytes32) {
        uint256 length = chainDigestArray.length;

        bytes32[] memory a = EfficientHashLib.malloc(length);
        for (uint256 i; i < length; i++) {
            a.set(i, chainDigestArray[i].hashChainDigestMimicRPC());
        }
        return a.hash();
    }

    /**
     * We have session digests, not full Session structs
     * However to mimic signTypedData() behavior, we need to use CHAIN_SESSION_TYPEHASH
     * not CHAIN_DIGEST_TYPEHASH. We just use the ready session digest instead of rebuilding it
     */
    function hashChainDigestMimicRPC(ChainDigest memory chainDigest) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                CHAIN_SESSION_TYPEHASH,
                chainDigest.chainId,
                chainDigest.sessionDigest // this is the digest obtained using sessionDigest()
                    // we just do not rebuild it here for all sessions, but receive it from off-chain
            )
        );
    }

    /**
     * Hashes the data from the Session struct with some security critical data
     * such as nonce, account address, smart session address, and mode
     */
    function sessionDigest(
        Session memory session,
        address account,
        SmartSessionMode mode,
        uint256 nonce
    )
        internal
        view
        returns (bytes32)
    {
        return _sessionDigest(session, account, address(this), mode, nonce);
    }

    /**
     * Should never be used directly on-chain, only via sessionDigest()
     * Only for external use - to be able to pass smartSession when
     * testing for different chains which may have different addresses for
     * the Smart Session contract
     * It is exactly how signTypedData will hash such an object
     * when this object is an inner struct
     * It won't use eip712 domain for it as it is inner struct
     */
    function _sessionDigest(
        Session memory session,
        address account,
        address smartSession, // for testing purposes
        SmartSessionMode mode,
        uint256 nonce
    )
        internal
        pure
        returns (bytes32 _hash)
    {
        // chainId is not needed as it is in the ChainSession
        _hash = keccak256(
            abi.encode(
                SESSION_TYPEHASH,
                account,
                smartSession,
                uint8(mode), // Include mode as uint8
                address(session.sessionValidator),
                session.salt,
                keccak256(session.sessionValidatorInitData),
                session.userOpPolicies.hashPolicyDataArray(),
                session.erc7739Policies.hashERC7739Data(),
                session.actions.hashActionDataArray(),
                nonce
            )
        );
    }

    function hashPolicyData(PolicyData memory policyData) internal pure returns (bytes32) {
        return keccak256(abi.encode(POLICY_DATA_TYPEHASH, policyData.policy, keccak256(policyData.initData)));
    }

    function hashPolicyDataArray(PolicyData[] memory policyDataArray) internal pure returns (bytes32) {
        uint256 length = policyDataArray.length;

        bytes32[] memory a = EfficientHashLib.malloc(length);
        for (uint256 i; i < length; i++) {
            a.set(i, policyDataArray[i].hashPolicyData());
        }
        return a.hash();
    }

    function hashActionData(ActionData memory actionData) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                ACTION_DATA_TYPEHASH,
                actionData.actionTargetSelector,
                actionData.actionTarget,
                hashPolicyDataArray(actionData.actionPolicies)
            )
        );
    }

    function hashActionDataArray(ActionData[] memory actionDataArray) internal pure returns (bytes32) {
        uint256 length = actionDataArray.length;
        bytes32[] memory a = EfficientHashLib.malloc(length);

        for (uint256 i; i < length; i++) {
            a.set(i, actionDataArray[i].hashActionData());
        }
        return a.hash();
    }

    function hashERC7739Context(ERC7739Context memory erc7739Context) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                ERC7739_CONTEXT_TYPEHASH,
                erc7739Context.appDomainSeparator,
                hashStringArray(erc7739Context.contentNames)
            )
        );
    }

    function hashERC7739ContextArray(ERC7739Context[] memory erc7739Context) internal pure returns (bytes32) {
        uint256 length = erc7739Context.length;
        bytes32[] memory a = EfficientHashLib.malloc(length);

        for (uint256 i; i < length; i++) {
            a.set(i, erc7739Context[i].hashERC7739Context());
        }
        return a.hash();
    }

    function hashERC7739Data(ERC7739Data memory erc7739Data) internal pure returns (bytes32) {
        bytes32[] memory a = EfficientHashLib.malloc(3);
        a.set(0, ERC7739_DATA_TYPEHASH);
        a.set(1, erc7739Data.allowedERC7739Content.hashERC7739ContextArray());
        a.set(2, erc7739Data.erc1271Policies.hashPolicyDataArray());
        return a.hash();
    }

    function hashStringArray(string[] memory stringArray) internal pure returns (bytes32) {
        uint256 length = stringArray.length;
        bytes32[] memory a = EfficientHashLib.malloc(length);
        for (uint256 i; i < length; i++) {
            a.set(i, keccak256(abi.encodePacked(stringArray[i])));
        }
        return a.hash();
    }

    function hashERC7739Content(string memory content) internal pure returns (bytes32) {
        return keccak256(bytes(content));
    }

    function getAndVerifyDigest(
        EnableSession memory enableData,
        address account,
        uint256 nonce,
        SmartSessionMode mode
    )
        internal
        view
        returns (bytes32 digest)
    {
        bytes32 computedHash = enableData.sessionToEnable.sessionDigest(account, mode, nonce);

        uint64 providedChainId = enableData.hashesAndChainIds[enableData.chainDigestIndex].chainId;
        bytes32 providedHash = enableData.hashesAndChainIds[enableData.chainDigestIndex].sessionDigest;

        if (providedChainId != block.chainid) {
            revert ChainIdMismatch(providedChainId);
        }

        // ensure digest we've built from the sessionToEnable is included into
        // the list of digests that were signed
        if (providedHash != computedHash) {
            revert HashMismatch(providedHash, computedHash);
        }

        digest = enableData.hashesAndChainIds.multichainDigest();
    }
}