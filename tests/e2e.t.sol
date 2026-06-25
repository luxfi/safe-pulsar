// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {Pulsar} from "contracts/Pulsar.sol";
import {SafePulsarSigner} from "contracts/SafePulsarSigner.sol";
import {SafePulsarCoSigner} from "contracts/SafePulsarCoSigner.sol";
import {PulsarAccount} from "contracts/PulsarAccount.sol";
import {ISafe} from "contracts/interfaces/ISafe.sol";
import {IERC1271} from "contracts/interfaces/IERC1271.sol";
import {PackedUserOperation} from "contracts/interfaces/IERC4337.sol";
import {MockPulsarPrecompile} from "./Pulsar.t.sol";

/// @notice A minimal Safe stand-in exposing exactly the surface the
/// {SafePulsarCoSigner} guard reads (`nonce`, `getTransactionHash`). It lets us
/// drive the guard's `checkTransaction` with a real Safe-tx hash without
/// pulling in the full Safe singleton + proxy factory (whose FROST deployment
/// helpers are Rust-FFI-driven). The guard's logic — slice the appended
/// co-signature, bind the key, verify — is exercised faithfully.
contract MockSafe {
    uint256 public nonce = 1; // guard reads nonce()-1, so 0 is the "current" tx
    bytes32 public immutable txHash;

    constructor(bytes32 txHash_) {
        txHash = txHash_;
    }

    function getTransactionHash(
        address,
        uint256,
        bytes calldata,
        uint8,
        uint256,
        uint256,
        uint256,
        address,
        address,
        uint256
    ) external view returns (bytes32) {
        return txHash;
    }
}

contract E2ETest is Test {
    uint8 internal mode;
    bytes internal pubkey;
    bytes32 internal msgHash;
    bytes internal sig;
    bytes internal expectedInput;

    address internal constant ENTRY_POINT = address(0xEE);

    function setUp() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/tests/kat.json"));
        mode = uint8(vm.parseJsonUint(json, ".mode"));
        pubkey = vm.parseJsonBytes(json, ".pubkey");
        msgHash = bytes32(vm.parseJsonBytes(json, ".msgHash"));
        sig = vm.parseJsonBytes(json, ".sig");
        expectedInput = vm.parseJsonBytes(json, ".input");

        vm.etch(Pulsar.PRECOMPILE, type(MockPulsarPrecompile).runtimeCode);
        vm.store(Pulsar.PRECOMPILE, bytes32(uint256(0)), keccak256(expectedInput));
    }

    /// @notice The ABI-encoded `(pubkey, sig)` contract-signature payload the
    /// Safe forwards for a Pulsar owner / account.
    function _payload() internal view returns (bytes memory) {
        return abi.encode(pubkey, sig);
    }

    // --- SafePulsarSigner: EIP-1271 owner ------------------------------------

    function test_Signer_ReturnsMagicValueForValidSignature() external {
        SafePulsarSigner signer = new SafePulsarSigner(mode, pubkey);
        bytes4 magic = signer.isValidSignature(msgHash, _payload());
        assertEq(magic, IERC1271.isValidSignature.selector, "valid Pulsar sig must yield ERC-1271 magic value");
    }

    function test_Signer_LegacyERC1271FailsClosedForWrongHash() external {
        SafePulsarSigner signer = new SafePulsarSigner(mode, pubkey);
        // The legacy path hashes the message; keccak256("legacy...") != msgHash,
        // so the framed precompile calldata won't match the KAT input and the
        // legacy selector path must return 0 (fail-closed), proving it is wired
        // through {Pulsar.verify}.
        bytes memory message = "legacy-erc1271-message";
        bytes4 magic = signer.isValidSignature(message, _payload());
        assertEq(magic, bytes4(0), "legacy path must fail-closed for a non-matching message hash");
    }

    function test_Signer_RejectsWrongKeyBinding() external {
        SafePulsarSigner signer = new SafePulsarSigner(mode, pubkey);
        // Supply a different (but correctly-sized) public key: the keccak
        // commitment won't match, so verification fails without a precompile
        // call.
        bytes memory otherPk = bytes.concat(pubkey);
        otherPk[0] ^= 0xFF;
        bytes memory badPayload = abi.encode(otherPk, sig);
        bytes4 magic = signer.isValidSignature(msgHash, badPayload);
        assertEq(magic, bytes4(0), "wrong key must not yield magic value");
    }

    function test_Signer_RejectsTamperedSignature() external {
        SafePulsarSigner signer = new SafePulsarSigner(mode, pubkey);
        bytes memory bad = bytes.concat(sig);
        bad[200] ^= 0xFF;
        bytes4 magic = signer.isValidSignature(msgHash, abi.encode(pubkey, bad));
        assertEq(magic, bytes4(0), "tampered sig must not yield magic value");
    }

    function test_Signer_ConstructorRejectsBadMode() external {
        vm.expectRevert(SafePulsarSigner.InvalidMode.selector);
        new SafePulsarSigner(0x99, pubkey);
    }

    function test_Signer_ConstructorRejectsWrongPubkeyLength() external {
        vm.expectRevert(SafePulsarSigner.InvalidPublicKey.selector);
        new SafePulsarSigner(mode, new bytes(pubkey.length - 1));
    }

    // --- SafePulsarCoSigner: transaction guard -------------------------------

    function test_CoSigner_AcceptsCoSignedTransaction() external {
        SafePulsarCoSigner coSigner = new SafePulsarCoSigner(mode, pubkey);
        MockSafe safe = new MockSafe(msgHash);

        // The Safe signatures blob: some leading owner signature bytes followed
        // by the appended Pulsar co-signature tuple. The guard slices the
        // trailing `coSignatureLength` bytes.
        bytes memory leading = abi.encodePacked(uint256(uint160(address(this))), uint256(0), uint8(1));
        bytes memory signatures = bytes.concat(leading, _payload());

        // Must not revert.
        vm.prank(address(safe));
        coSigner.checkTransaction(
            address(safe), 0, "", 0, 0, 0, 0, address(0), payable(address(0)), signatures, address(this)
        );
        assertEq(coSigner.coSignatureLength(), _payload().length, "coSignatureLength must equal tuple length");
    }

    function test_CoSigner_RevertsWithoutCoSignature() external {
        SafePulsarCoSigner coSigner = new SafePulsarCoSigner(mode, pubkey);
        MockSafe safe = new MockSafe(msgHash);

        // Tamper the appended signature so verification fails.
        bytes memory bad = bytes.concat(sig);
        bad[300] ^= 0xFF;
        bytes memory signatures = abi.encode(pubkey, bad);

        vm.prank(address(safe));
        vm.expectRevert(SafePulsarCoSigner.Unauthorized.selector);
        coSigner.checkTransaction(
            address(safe), 0, "", 0, 0, 0, 0, address(0), payable(address(0)), signatures, address(this)
        );
    }

    function test_CoSigner_RevertsOnShortSignatures() external {
        SafePulsarCoSigner coSigner = new SafePulsarCoSigner(mode, pubkey);
        MockSafe safe = new MockSafe(msgHash);
        vm.prank(address(safe));
        vm.expectRevert(SafePulsarCoSigner.Unauthorized.selector);
        coSigner.checkTransaction(
            address(safe), 0, "", 0, 0, 0, 0, address(0), payable(address(0)), hex"deadbeef", address(this)
        );
    }

    // --- PulsarAccount: ERC-4337 ---------------------------------------------

    function test_Account_ValidatesUserOp() external {
        PulsarAccount account = new PulsarAccount(ENTRY_POINT, mode, pubkey);
        PackedUserOperation memory userOp = _emptyUserOp();
        userOp.signature = _payload();

        vm.prank(ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, msgHash, 0);
        assertEq(validationData, 0, "valid Pulsar user op must validate (0)");
    }

    function test_Account_RejectsTamperedUserOp() external {
        PulsarAccount account = new PulsarAccount(ENTRY_POINT, mode, pubkey);
        PackedUserOperation memory userOp = _emptyUserOp();
        bytes memory bad = bytes.concat(sig);
        bad[400] ^= 0xFF;
        userOp.signature = abi.encode(pubkey, bad);

        vm.prank(ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, msgHash, 0);
        assertEq(validationData, 1, "tampered Pulsar user op must fail validation (1)");
    }

    function test_Account_RejectsWrongKeyBinding() external {
        PulsarAccount account = new PulsarAccount(ENTRY_POINT, mode, pubkey);
        PackedUserOperation memory userOp = _emptyUserOp();
        bytes memory otherPk = bytes.concat(pubkey);
        otherPk[1] ^= 0xFF;
        userOp.signature = abi.encode(otherPk, sig);

        vm.prank(ENTRY_POINT);
        uint256 validationData = account.validateUserOp(userOp, msgHash, 0);
        assertEq(validationData, 1, "wrong key user op must fail validation (1)");
    }

    function test_Account_OnlyEntryPoint() external {
        PulsarAccount account = new PulsarAccount(ENTRY_POINT, mode, pubkey);
        PackedUserOperation memory userOp = _emptyUserOp();
        userOp.signature = _payload();
        vm.expectRevert(PulsarAccount.UnsupportedEntryPoint.selector);
        account.validateUserOp(userOp, msgHash, 0);
    }

    function _emptyUserOp() internal pure returns (PackedUserOperation memory userOp) {
        userOp = PackedUserOperation({
            sender: address(0),
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
    }
}
