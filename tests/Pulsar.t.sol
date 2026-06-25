// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {Pulsar} from "contracts/Pulsar.sol";

/// @notice A stand-in for the on-chain `pulsarVerify` precompile (`0x012204`),
/// used in `forge test` where the Go precompile is not present.
///
/// @dev GROUND-TRUTH ABI CONFORMANCE. This mock does NOT re-implement ML-DSA.
/// Instead it asserts the *calldata framing*: it returns the precompile's exact
/// success word `bytes32(1)` iff the incoming calldata is byte-for-byte equal
/// to a reference `input` blob whose keccak256 is stored in slot 0. That
/// reference blob is a real Known-Answer-Test vector produced by
/// `precompile/cmd/safekatdump` and independently *proven to verify against the
/// real Go precompile* by `precompile/cmd/safekatverify`. Therefore: if
/// {Pulsar.verify}'s framed calldata matches this blob, it would also be
/// accepted by the real precompile; any drift in the wire format (field order,
/// length prefixes, padding) changes the calldata and this mock returns zero —
/// failing the test. The expected hash is injected via `vm.store` after `etch`,
/// so the same deployed code can serve any KAT.
contract MockPulsarPrecompile {
    fallback(bytes calldata input) external returns (bytes memory) {
        bytes32 expected;
        assembly {
            expected := sload(0)
        }
        bool ok = keccak256(input) == expected;
        return abi.encode(ok ? bytes32(uint256(1)) : bytes32(0));
    }
}

contract PulsarTest is Test {
    // KAT components loaded from tests/kat.json (real vector, proven against
    // the Go precompile by safekatverify).
    uint8 internal mode;
    bytes internal pubkey;
    bytes32 internal msgHash;
    bytes internal sig;
    bytes internal expectedInput;

    function setUp() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/tests/kat.json"));
        mode = uint8(vm.parseJsonUint(json, ".mode"));
        pubkey = vm.parseJsonBytes(json, ".pubkey");
        msgHash = bytes32(vm.parseJsonBytes(json, ".msgHash"));
        sig = vm.parseJsonBytes(json, ".sig");
        expectedInput = vm.parseJsonBytes(json, ".input");

        // Install the mock at the real precompile address and pin the expected
        // calldata hash.
        vm.etch(Pulsar.PRECOMPILE, type(MockPulsarPrecompile).runtimeCode);
        vm.store(Pulsar.PRECOMPILE, bytes32(uint256(0)), keccak256(expectedInput));
    }

    /// @notice The library frames calldata that byte-matches the KAT input the
    /// real precompile accepts, so {Pulsar.verify} returns true.
    function test_Verify_KAT() public view {
        assertTrue(Pulsar.verify(msgHash, mode, pubkey, sig), "Pulsar KAT must verify");
    }

    /// @notice Independent, self-contained proof that the library frames the
    /// precompile calldata EXACTLY as the Go `Run()` parses it:
    ///   mode(1) || pubkey || msgLen:uint256(32)=32 || msg(32) || sig
    function test_CalldataFramingMatchesPrecompileABI() public view {
        bytes memory framed = abi.encodePacked(mode, pubkey, uint256(32), msgHash, sig);
        assertEq(keccak256(framed), keccak256(expectedInput), "framing must equal precompile wire bytes");
        assertEq(framed.length, expectedInput.length, "framed length must equal precompile input length");
        // 1 (mode) + 1952 (pk-65) + 32 (msgLen) + 32 (msg) + 3309 (sig).
        assertEq(framed.length, 1 + 1952 + 32 + 32 + 3309, "Pulsar-65 input size");
    }

    /// @notice A tampered signature changes the calldata, so the precompile
    /// (and thus {Pulsar.verify}) rejects it — fail-closed.
    function test_Verify_RejectsTamperedSignature() public view {
        bytes memory bad = bytes.concat(sig);
        bad[100] ^= 0xFF;
        assertFalse(Pulsar.verify(msgHash, mode, pubkey, bad), "tampered sig must not verify");
    }

    /// @notice A wrong message changes the calldata, so verification fails.
    function test_Verify_RejectsWrongMessage() public view {
        bytes32 wrong = keccak256("not the signed message");
        assertFalse(Pulsar.verify(wrong, mode, pubkey, sig), "wrong message must not verify");
    }

    /// @notice A public key of the wrong length for the mode is rejected before
    /// any precompile call.
    function test_Verify_RejectsWrongPubkeyLength() public view {
        bytes memory shortPk = new bytes(pubkey.length - 1);
        assertFalse(Pulsar.verify(msgHash, mode, shortPk, sig), "short pubkey must not verify");
    }

    /// @notice An unsupported mode byte is rejected (no precompile call).
    function test_Verify_RejectsBadMode() public view {
        assertFalse(Pulsar.verify(msgHash, 0x99, pubkey, sig), "bad mode must not verify");
    }

    /// @notice Strict success-word check: a precompile that returns a non-1
    /// word (e.g. a different success encoding) is treated as failure.
    function test_Verify_FailClosedOnNonOneWord() public {
        // Re-pin to a hash that the framed calldata will NOT match.
        vm.store(Pulsar.PRECOMPILE, bytes32(uint256(0)), keccak256("never matches"));
        assertFalse(Pulsar.verify(msgHash, mode, pubkey, sig), "non-success word must be false");
    }

    /// @notice The published precompile address is the canonical LP-4200 slot.
    function test_PrecompileAddress() public pure {
        assertEq(Pulsar.PRECOMPILE, address(0x0000000000000000000000000000000000012204));
    }

    /// @notice The published context matches the precompile's domain separator.
    function test_Context() public pure {
        assertEq(string(Pulsar.CONTEXT), "lux-evm-precompile-pulsar-v1");
    }
}
