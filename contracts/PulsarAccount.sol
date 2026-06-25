// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.29;

import {Pulsar} from "./Pulsar.sol";
import {IERC4337, PackedUserOperation} from "./interfaces/IERC4337.sol";

/// @title Pulsar Account
/// @notice An ERC-4337 account whose user operations are authorised by a
/// committed Pulsar threshold-ML-DSA (FIPS 204) key, verified through the
/// `pulsarVerify` precompile.
///
/// @dev BINDING. Unlike the secp256k1 FROST account (which recovers an address
/// from the public key and checks it equals `address(this)`), a post-quantum
/// key has no address-recovery trick. The account instead commits
/// `(mode, keccak256(pubkey))` at construction. The user-operation signature
/// carries the full public key and Pulsar signature; the key is re-hashed
/// against the commitment, then the signature is verified over `userOpHash`.
///
/// REPLAY. `userOpHash` is bound by the EntryPoint to this account, the chain
/// id and the nonce, so a Pulsar signature over it authorises exactly one
/// operation. The precompile additionally binds the Pulsar context.
///
/// SIGNATURE PAYLOAD: `abi.encode(bytes pubkey, bytes pulsarSignature)`.
contract PulsarAccount is IERC4337 {
    /// @notice The supported ERC-4337 entry point contract.
    address private immutable _ENTRY_POINT;
    /// @notice The Pulsar parameter-set byte this account verifies under.
    uint8 private immutable _MODE;
    /// @notice keccak256 of the committed Pulsar group public key.
    bytes32 private immutable _PUBKEY_HASH;

    /// @notice Attempt to call a function reserved for the entry point.
    error UnsupportedEntryPoint();
    /// @notice The mode is not a recognised Pulsar parameter set.
    error InvalidMode();
    /// @notice The supplied public key length is wrong for the mode.
    error InvalidPublicKey();

    /// @param entryPoint The ERC-4337 entry point contract.
    /// @param mode The Pulsar parameter-set byte (0x44, 0x65 or 0x87).
    /// @param pubkey The full FIPS 204 group public key to bind this account to.
    constructor(address entryPoint, uint8 mode, bytes memory pubkey) {
        require(Pulsar.isValidMode(mode), InvalidMode());
        (uint256 pkLen,) = Pulsar.sizes(mode);
        require(pubkey.length == pkLen, InvalidPublicKey());
        _ENTRY_POINT = entryPoint;
        _MODE = mode;
        _PUBKEY_HASH = keccak256(pubkey);
    }

    receive() external payable {}

    /// @notice Function must be called by the entry point.
    modifier onlyEntryPoint() {
        require(msg.sender == _ENTRY_POINT, UnsupportedEntryPoint());
        _;
    }

    /// @inheritdoc IERC4337
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        if (missingAccountFunds != 0) {
            assembly ("memory-safe") {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
        }

        (bytes memory pubkey, bytes memory pulsarSignature) = abi.decode(userOp.signature, (bytes, bytes));
        if (keccak256(pubkey) != _PUBKEY_HASH) return 1;
        return Pulsar.verify(userOpHash, _MODE, pubkey, pulsarSignature) ? 0 : 1;
    }

    /// @notice Execute a transaction.
    /// @param target The call target.
    /// @param value The native token value to send.
    /// @param data The call data.
    function execute(address target, uint256 value, bytes calldata data) external onlyEntryPoint {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, data.offset, data.length)

            if iszero(call(gas(), target, value, ptr, data.length, 0, 0)) {
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
        }
    }
}
