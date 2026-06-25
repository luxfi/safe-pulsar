// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.29;

import {Pulsar} from "./Pulsar.sol";
import {IERC1271, ILegacyERC1271} from "./interfaces/IERC1271.sol";

/// @title Safe Pulsar Signer
/// @notice Safe smart-account owner that verifies Pulsar threshold-ML-DSA
/// (FIPS 204) signatures through the `pulsarVerify` precompile, making a single
/// Pulsar group public key a first-class Safe owner via EIP-1271.
///
/// @dev ONE key, ONE owner. The owner commits to a single `(mode, pubKeyHash)`
/// pair at construction; both are `immutable`, so the contract holds NO mutable
/// storage and `isValidSignature` is a pure `view`. (A state-changing EIP-1271
/// validator is rejected by the Safe's staticcall/gas guard; being stateless
/// side-steps that hazard entirely.)
///
/// BINDING. We commit only `keccak256(pubkey)`, not the ~2 KB public key — one
/// 32-byte immutable, and an attacker cannot present a different key whose
/// keccak256 matches (second-preimage resistance). The full key is supplied at
/// verify time inside the signature blob and re-hashed against the commitment,
/// closing the "attacker supplies an arbitrary public key" attack.
///
/// REPLAY. The Safe passes the EIP-712 Safe-transaction hash, which is bound to
/// this Safe's address, the chain id and the tx nonce — so a Pulsar signature
/// over it is valid for exactly one Safe / chain / nonce. The precompile
/// additionally binds the `"lux-evm-precompile-pulsar-v1"` context, preventing
/// cross-precompile replay against the single-party ML-DSA slot.
///
/// SIGNATURE PAYLOAD: `abi.encode(bytes pubkey, bytes pulsarSignature)`.
contract SafePulsarSigner is IERC1271, ILegacyERC1271 {
    /// @notice The Pulsar parameter-set byte this owner verifies under.
    uint8 private immutable _MODE;
    /// @notice keccak256 of the committed Pulsar group public key.
    bytes32 private immutable _PUBKEY_HASH;

    /// @notice The mode is not a recognised Pulsar parameter set.
    error InvalidMode();
    /// @notice The supplied public key length is wrong for the mode.
    error InvalidPublicKey();

    /// @param mode The Pulsar parameter-set byte (0x44, 0x65 or 0x87).
    /// @param pubkey The full FIPS 204 group public key to bind this owner to.
    constructor(uint8 mode, bytes memory pubkey) {
        require(Pulsar.isValidMode(mode), InvalidMode());
        (uint256 pkLen,) = Pulsar.sizes(mode);
        require(pubkey.length == pkLen, InvalidPublicKey());
        _MODE = mode;
        _PUBKEY_HASH = keccak256(pubkey);
    }

    /// @notice Checks if the given signature is valid for the given message.
    /// @param message The message to be verified (the Safe tx hash).
    /// @param signature `abi.encode(bytes pubkey, bytes pulsarSignature)`.
    /// @return ok Whether or not the signature is valid.
    function _isValidSignature(bytes32 message, bytes calldata signature) public view returns (bool ok) {
        (bytes memory pubkey, bytes memory pulsarSignature) = abi.decode(signature, (bytes, bytes));
        if (keccak256(pubkey) != _PUBKEY_HASH) return false;
        return Pulsar.verify(message, _MODE, pubkey, pulsarSignature);
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 message, bytes calldata signature) public view returns (bytes4 magicValue) {
        if (_isValidSignature(message, signature)) {
            magicValue = IERC1271.isValidSignature.selector;
        }
    }

    /// @inheritdoc ILegacyERC1271
    function isValidSignature(bytes memory message, bytes calldata signature) public view returns (bytes4 magicValue) {
        if (_isValidSignature(keccak256(message), signature)) {
            magicValue = ILegacyERC1271.isValidSignature.selector;
        }
    }
}
