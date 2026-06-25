// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.29;

import {Pulsar} from "./Pulsar.sol";
import {ISafe} from "./interfaces/ISafe.sol";
import {IERC165, ISafeTransactionGuard} from "./interfaces/ISafeTransactionGuard.sol";

/// @title Safe Pulsar Co-Signer
/// @notice A Safe transaction guard that additionally requires every Safe
/// transaction to be co-signed by a committed Pulsar threshold-ML-DSA key. Add
/// it with `setGuard`; thereafter `execTransaction` reverts unless the appended
/// Pulsar co-signature verifies over the Safe-tx hash.
///
/// @dev DECOMPLECTION: the guard enforces ONE policy — "a valid Pulsar
/// co-signature for this owner's key must be present". The cryptographic verify
/// is delegated wholly to {Pulsar}; pubkey↔owner binding is the committed
/// `keccak256(pubkey)`.
///
/// CO-SIGNATURE LAYOUT. The Pulsar signature is variable length, so it is
/// appended to the Safe `signatures` bytes as a self-describing, ABI-encoded
/// `(bytes pubkey, bytes pulsarSignature)` tuple whose total length is
/// `coSignatureLength`. The guard slices exactly the trailing
/// `coSignatureLength` bytes and `abi.decode`s them — `abi.decode` validates
/// the offsets/lengths and reverts on a malformed tail, failing closed before
/// any precompile call.
contract SafePulsarCoSigner is ISafeTransactionGuard {
    /// @notice The Pulsar parameter-set byte this co-signer verifies under.
    uint8 private immutable _MODE;
    /// @notice keccak256 of the committed Pulsar group public key.
    bytes32 private immutable _PUBKEY_HASH;
    /// @notice The exact byte length of the appended co-signature tuple.
    uint256 private immutable _COSIG_LEN;

    /// @notice The transaction was not co-signed by the committed Pulsar key.
    error Unauthorized();
    /// @notice The mode is not a recognised Pulsar parameter set.
    error InvalidMode();
    /// @notice The supplied public key length is wrong for the mode.
    error InvalidPublicKey();

    /// @param mode The Pulsar parameter-set byte (0x44, 0x65 or 0x87).
    /// @param pubkey The full FIPS 204 group public key to bind this co-signer to.
    constructor(uint8 mode, bytes memory pubkey) {
        require(Pulsar.isValidMode(mode), InvalidMode());
        (uint256 pkLen, uint256 sigLen) = Pulsar.sizes(mode);
        require(pubkey.length == pkLen, InvalidPublicKey());
        _MODE = mode;
        _PUBKEY_HASH = keccak256(pubkey);
        // abi.encode(bytes pubkey, bytes sig) = 0x40 head (two offsets) +
        // 0x20 len + ceil(pkLen) + 0x20 len + ceil(sigLen), each tail padded to
        // a 32-byte boundary.
        _COSIG_LEN = 0x40 + 0x20 + _ceil32(pkLen) + 0x20 + _ceil32(sigLen);
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) external view virtual override returns (bool) {
        return interfaceId == type(ISafeTransactionGuard).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    /// @notice The expected length of the appended Pulsar co-signature tuple.
    function coSignatureLength() external view returns (uint256) {
        return _COSIG_LEN;
    }

    /// @inheritdoc ISafeTransactionGuard
    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures,
        address
    ) external view {
        bytes32 safeTxHash;
        unchecked {
            uint256 nonce = ISafe(msg.sender).nonce() - 1;
            safeTxHash = ISafe(msg.sender).getTransactionHash(
                to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce
            );
        }

        // The co-signature is the trailing `_COSIG_LEN` bytes of `signatures`.
        require(signatures.length >= _COSIG_LEN, Unauthorized());
        bytes calldata coSignature = signatures[signatures.length - _COSIG_LEN:];
        (bytes memory pubkey, bytes memory pulsarSignature) = abi.decode(coSignature, (bytes, bytes));

        require(keccak256(pubkey) == _PUBKEY_HASH, Unauthorized());
        require(Pulsar.verify(safeTxHash, _MODE, pubkey, pulsarSignature), Unauthorized());
    }

    /// @inheritdoc ISafeTransactionGuard
    function checkAfterExecution(bytes32, bool) external pure {}

    /// @notice Rounds `n` up to the next 32-byte boundary.
    function _ceil32(uint256 n) private pure returns (uint256) {
        return (n + 31) & ~uint256(31);
    }
}
