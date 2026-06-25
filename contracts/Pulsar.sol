// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.29;

/// @title Pulsar Library
/// @notice Library for verifying Pulsar threshold ML-DSA (FIPS 204) signatures
/// through the Lux on-chain `pulsarVerify` precompile at `0x012204`.
///
/// @dev DECOMPLECTION. This library does ONE thing: turn a Pulsar
/// `(mode, pubkey, signature, hash)` into a boolean by framing the calldata
/// the on-chain precompile expects and staticcalling it under a strict
/// success-word check. It holds no state, enforces no policy, and never
/// reverts on a cryptographic "false". Ownership / threshold policy lives in
/// the Safe; pubkey↔owner binding lives in {SafePulsarSigner} / the account.
///
/// CRYPTOGRAPHIC IDENTITY. Pulsar (`github.com/luxfi/pulsar`) is a Module-LWE
/// threshold signature whose verification operation is *literally identical*
/// to FIPS 204 ML-DSA.Verify — a signature produced by a Pulsar threshold
/// ceremony (DKG + Round1 + Round2 + Combine) is byte-equal to a single-party
/// FIPS 204 signature on the same message and group public key. The precompile
/// therefore dispatches to the ML-DSA verifier under the hood; the dedicated
/// `0x012204` slot binds the verification to "this came from a threshold
/// ceremony" and carries its own domain-separation context.
///
/// DOMAIN SEPARATION. The precompile binds the FIPS context string
/// `"lux-evm-precompile-pulsar-v1"` into verification. A signature is valid
/// only under that exact context: a Pulsar signature cannot be replayed
/// against the single-party ML-DSA precompile (`0x012202`, context
/// `"lux-evm-precompile-mldsa-v1"`) or any other PQ slot. The signing client
/// MUST sign with the Pulsar context — see {Pulsar.CONTEXT}.
///
/// WIRE FORMAT (must match `github.com/luxfi/precompile/pulsar`.Run
/// byte-for-byte):
///
///     mode(1) ‖ pubkey ‖ msgLen:uint256(32) ‖ message ‖ signature
///
/// For all Safe uses the "message" is the 32-byte Safe-tx hash, so `msgLen`
/// is fixed to 32. The precompile reads the low 8 bytes of `msgLen` as the
/// length, then slices `pubkey`/`message`/`signature` by the mode's fixed
/// sizes; trailing bytes beyond the implied size are ignored by the
/// precompile, but {verify} frames the exact length so the call is canonical.
///
/// FAIL-CLOSED. The precompile returns the empty-success / typed-error
/// convention of the threshold family; on the EVM boundary a *successful*
/// staticcall that yields the success word is the only "true". {verify}
/// treats anything else — revert, wrong-size return, zero word, missing
/// precompile — as `false`. Mirrors the hardened pattern in
/// `luxfi/safe/contracts/pq/PQVerifier.sol`.
library Pulsar {
    /// @notice The canonical LP-4200 on-chain address of the Pulsar
    /// threshold-ML-DSA verify precompile.
    address internal constant PRECOMPILE = 0x0000000000000000000000000000000000012204;

    /// @notice The FIPS domain-separation context the precompile binds. The
    /// signing client MUST use this exact context or the signature will not
    /// verify on-chain. Exposed for off-chain reference; the precompile
    /// re-derives it and it is not part of the calldata.
    bytes internal constant CONTEXT = "lux-evm-precompile-pulsar-v1";

    // --- Pulsar parameter-set mode bytes (mirror FIPS 204 ML-DSA) ----------

    uint8 internal constant MODE_44 = 0x44; // NIST PQ Category 2
    uint8 internal constant MODE_65 = 0x65; // NIST PQ Category 3 (production target)
    uint8 internal constant MODE_87 = 0x87; // NIST PQ Category 5

    /// @notice Returns the FIPS 204 public-key and signature byte sizes for a
    /// Pulsar parameter-set mode.
    /// @dev Reverts on an unknown mode — an unsupported mode can never produce
    /// a valid signature, so a hard revert at the size lookup prevents binding
    /// an owner to an unverifiable configuration. Sizes per FIPS 204 Table 2.
    /// @param mode The Pulsar parameter-set byte.
    /// @return pkLen The public key length in bytes.
    /// @return sigLen The signature length in bytes.
    function sizes(uint8 mode) internal pure returns (uint256 pkLen, uint256 sigLen) {
        if (mode == MODE_44) return (1312, 2420);
        if (mode == MODE_65) return (1952, 3309);
        if (mode == MODE_87) return (2592, 4627);
        revert("Pulsar: bad mode");
    }

    /// @notice Whether `mode` is a recognised Pulsar parameter set.
    /// @param mode The Pulsar parameter-set byte.
    /// @return ok True iff the mode is 0x44, 0x65 or 0x87.
    function isValidMode(uint8 mode) internal pure returns (bool ok) {
        return mode == MODE_44 || mode == MODE_65 || mode == MODE_87;
    }

    /// @notice Verify a Pulsar threshold-ML-DSA signature over the 32-byte
    /// `hash` against `pubkey`, under the `mode` parameter set.
    /// @dev Rejects up-front if `pubkey`/`sig` are not the exact size for the
    /// mode (the precompile would reject a structurally invalid call anyway,
    /// but the length check keeps the framed call canonical and avoids paying
    /// gas to frame an obviously invalid input). Then frames the exact wire
    /// bytes and staticcalls {PRECOMPILE} fail-closed.
    /// @param hash The 32-byte message digest that was signed (the Safe tx hash).
    /// @param mode The Pulsar parameter-set byte (e.g. 0x65 for Pulsar-65).
    /// @param pubkey The raw FIPS 204 group public key bytes.
    /// @param sig The raw FIPS 204-byte-equal Pulsar signature bytes.
    /// @return ok True iff the precompile returned the exact success word.
    function verify(bytes32 hash, uint8 mode, bytes memory pubkey, bytes memory sig) internal view returns (bool ok) {
        if (!isValidMode(mode)) return false;
        (uint256 pkLen, uint256 sigLen) = sizes(mode);
        if (pubkey.length != pkLen || sig.length != sigLen) return false;

        // mode(1) ‖ pubkey ‖ msgLen:uint256(32)=32 ‖ hash(32) ‖ sig
        bytes memory input = abi.encodePacked(mode, pubkey, uint256(32), hash, sig);
        return _callStrict(input);
    }

    /// @notice Staticcall {PRECOMPILE} with `input`, returning true iff the
    /// call succeeded AND returned exactly the 32-byte word `bytes32(1)`.
    /// @dev Fail-closed on staticcall failure, any `returndatasize != 32`, any
    /// returned word != 1, and a missing precompile (`returndatasize == 0`).
    /// Memory-safe assembly avoids an allocation for the 32-byte return.
    /// @param input The framed precompile calldata.
    /// @return ok Whether the strict success word was returned.
    function _callStrict(bytes memory input) private view returns (bool ok) {
        assembly ("memory-safe") {
            let success := staticcall(gas(), PRECOMPILE, add(input, 0x20), mload(input), 0x00, 0x20)
            ok := and(success, and(eq(returndatasize(), 0x20), eq(mload(0x00), 1)))
        }
    }
}
