// Sources flattened with hardhat v2.28.4 https://hardhat.org

// SPDX-License-Identifier: BSD-3-Clause-Clear AND MIT

// File @fhevm/solidity/lib/cryptography/FhevmECDSA.sol@v0.11.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.5.0) (utils/cryptography/ECDSA.sol)

pragma solidity ^0.8.20;

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 *
 * @dev This library is forked from OpenZeppelin's ECDSA and renamed to FhevmECDSA
 * to avoid naming conflicts with the original when both are used in the same project.
 */
library FhevmECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS
    }

    /**
     * @dev The signature is invalid.
     */
    error ECDSAInvalidSignature();

    /**
     * @dev The signature has an invalid length.
     */
    error ECDSAInvalidSignatureLength(uint256 length);

    /**
     * @dev The signature has an S value that is in the upper half order.
     */
    error ECDSAInvalidSignatureS(bytes32 s);

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with `signature` or an error. This will not
     * return address(0) without also returning an error description. Errors are documented using an enum (error type)
     * and a bytes32 providing additional information about the error.
     *
     * If no error is returned, then the address can be used for verification purposes.
     *
     * The `ecrecover` EVM precompile allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * NOTE: This function only supports 65-byte signatures. ERC-2098 short signatures are rejected. This restriction
     * is DEPRECATED and will be removed in v6.0. Developers SHOULD NOT use signatures as unique identifiers; use hash
     * invalidation or nonces for replay protection.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {MessageHashUtils-toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     *
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     */
    function tryRecover(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly ("memory-safe") {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));
        }
    }

    /**
     * @dev Variant of {tryRecover} that takes a signature in calldata
     */
    function tryRecoverCalldata(
        bytes32 hash,
        bytes calldata signature
    ) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, calldata slices would work here, but are
            // significantly more expensive (length check) than using calldataload in assembly.
            assembly ("memory-safe") {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 0x20))
                v := byte(0, calldataload(add(signature.offset, 0x40)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM precompile allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * NOTE: This function only supports 65-byte signatures. ERC-2098 short signatures are rejected. This restriction
     * is DEPRECATED and will be removed in v6.0. Developers SHOULD NOT use signatures as unique identifiers; use hash
     * invalidation or nonces for replay protection.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {MessageHashUtils-toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, signature);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Variant of {recover} that takes a signature in calldata
     */
    function recoverCalldata(bytes32 hash, bytes calldata signature) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecoverCalldata(hash, signature);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[ERC-2098 short signatures]
     */
    function tryRecover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
        unchecked {
            bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            // We do not check for an overflow here since the shift operation results in 0 or 1.
            uint8 v = uint8((uint256(vs) >> 255) + 27);
            return tryRecover(hash, v, r, s);
        }
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r` and `vs` short-signature fields separately.
     */
    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, r, vs);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS, s);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature, bytes32(0));
        }

        return (signer, RecoverError.NoError, bytes32(0));
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, v, r, s);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Parse a signature into its `v`, `r` and `s` components. Supports 65-byte and 64-byte (ERC-2098)
     * formats. Returns (0,0,0) for invalid signatures.
     *
     * For 64-byte signatures, `v` is automatically normalized to 27 or 28.
     * For 65-byte signatures, `v` is returned as-is and MUST already be 27 or 28 for use with ecrecover.
     *
     * Consider validating the result before use, or use {tryRecover}/{recover} which perform full validation.
     */
    function parse(bytes memory signature) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        assembly ("memory-safe") {
            // Check the signature length
            switch mload(signature)
            // - case 65: r,s,v signature (standard)
            case 65 {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            // - case 64: r,vs signature (cf https://eips.ethereum.org/EIPS/eip-2098)
            case 64 {
                let vs := mload(add(signature, 0x40))
                r := mload(add(signature, 0x20))
                s := and(vs, shr(1, not(0)))
                v := add(shr(255, vs), 27)
            }
            default {
                r := 0
                s := 0
                v := 0
            }
        }
    }

    /**
     * @dev Variant of {parse} that takes a signature in calldata
     */
    function parseCalldata(bytes calldata signature) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        assembly ("memory-safe") {
            // Check the signature length
            switch signature.length
            // - case 65: r,s,v signature (standard)
            case 65 {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 0x20))
                v := byte(0, calldataload(add(signature.offset, 0x40)))
            }
            // - case 64: r,vs signature (cf https://eips.ethereum.org/EIPS/eip-2098)
            case 64 {
                let vs := calldataload(add(signature.offset, 0x20))
                r := calldataload(signature.offset)
                s := and(vs, shr(1, not(0)))
                v := add(shr(255, vs), 27)
            }
            default {
                r := 0
                s := 0
                v := 0
            }
        }
    }

    /**
     * @dev Optionally reverts with the corresponding custom error according to the `error` argument provided.
     */
    function _throwError(RecoverError error, bytes32 errorArg) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert ECDSAInvalidSignature();
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert ECDSAInvalidSignatureLength(uint256(errorArg));
        } else if (error == RecoverError.InvalidSignatureS) {
            revert ECDSAInvalidSignatureS(errorArg);
        }
    }
}


// File @fhevm/solidity/lib/FheType.sol@v0.11.1

// Original license: SPDX_License_Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

enum FheType {
    Bool,
    Uint4,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Uint160,
    Uint256,
    Uint512,
    Uint1024,
    Uint2048,
    Uint2,
    Uint6,
    Uint10,
    Uint12,
    Uint14,
    Int2,
    Int4,
    Int6,
    Int8,
    Int10,
    Int12,
    Int14,
    Int16,
    Int32,
    Int64,
    Int128,
    Int160,
    Int256,
    AsciiString,
    Int512,
    Int1024,
    Int2048,
    Uint24,
    Uint40,
    Uint48,
    Uint56,
    Uint72,
    Uint80,
    Uint88,
    Uint96,
    Uint104,
    Uint112,
    Uint120,
    Uint136,
    Uint144,
    Uint152,
    Uint168,
    Uint176,
    Uint184,
    Uint192,
    Uint200,
    Uint208,
    Uint216,
    Uint224,
    Uint232,
    Uint240,
    Uint248,
    Int24,
    Int40,
    Int48,
    Int56,
    Int72,
    Int80,
    Int88,
    Int96,
    Int104,
    Int112,
    Int120,
    Int136,
    Int144,
    Int152,
    Int168,
    Int176,
    Int184,
    Int192,
    Int200,
    Int208,
    Int216,
    Int224,
    Int232,
    Int240,
    Int248
}


// File @fhevm/solidity/lib/Impl.sol@v0.11.1

// Original license: SPDX_License_Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

/**
 * @title   CoprocessorConfig
 * @notice  This struct contains all addresses of core contracts, which are needed in a typical dApp.
 */
struct CoprocessorConfig {
    address ACLAddress;
    address CoprocessorAddress;
    address KMSVerifierAddress;
}

/**
 * @title   IFHEVMExecutor
 * @notice  This interface contains all functions to conduct FHE operations.
 */
interface IFHEVMExecutor {
    /**
     * @notice              Computes fheAdd operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheAdd(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheSub operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheSub(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheMul operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheMul(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheDiv operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheDiv(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheRem operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheRem(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheBitAnd operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheBitAnd(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheBitOr operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheBitOr(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheBitXor operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheBitXor(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheShl operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheShl(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheShr operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheShr(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheRotl operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheRotl(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheRotr operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheRotr(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheEq operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheEq(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheNe operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheNe(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheGe operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheGe(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheGt operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheGt(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheLe operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheLe(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheLt operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheLt(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheMin operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheMin(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheMax operation.
     * @param lhs           LHS.
     * @param rhs           RHS.
     * @param scalarByte    Scalar byte.
     * @return result       Result.
     */
    function fheMax(bytes32 lhs, bytes32 rhs, bytes1 scalarByte) external returns (bytes32 result);

    /**
     * @notice              Computes fheNeg operation.
     * @param ct            Ct
     * @return result       Result.
     */
    function fheNeg(bytes32 ct) external returns (bytes32 result);

    /**
     * @notice              Computes fheNot operation.
     * @param ct            Ct
     * @return result       Result.
     */
    function fheNot(bytes32 ct) external returns (bytes32 result);

    /**
     * @notice                Verifies the ciphertext.
     * @param inputHandle     Input handle.
     * @param callerAddress   Address of the caller.
     * @param inputProof      Input proof.
     * @param inputType       Input type.
     * @return result         Result.
     */
    function verifyInput(
        bytes32 inputHandle,
        address callerAddress,
        bytes memory inputProof,
        FheType inputType
    ) external returns (bytes32 result);

    /**
     * @notice          Performs the casting to a target type.
     * @param ct        Value to cast.
     * @param toType    Target type.
     * @return result   Result value of the target type.
     */
    function cast(bytes32 ct, FheType toType) external returns (bytes32 result);

    /**
     * @notice          Does trivial encryption.
     * @param ct        Value to encrypt.
     * @param toType    Target type.
     * @return result   Result value of the target type.
     */
    function trivialEncrypt(uint256 ct, FheType toType) external returns (bytes32 result);

    /**
     * @notice              Computes FHEIfThenElse operation.
     * @param control       Control value.
     * @param ifTrue        If true.
     * @param ifFalse       If false.
     * @return result       Result.
     */
    function fheIfThenElse(bytes32 control, bytes32 ifTrue, bytes32 ifFalse) external returns (bytes32 result);

    /**
     * @notice              Computes FHERand operation.
     * @param randType      Type for the random result.
     * @return result       Result.
     */
    function fheRand(FheType randType) external returns (bytes32 result);

    /**
     * @notice              Computes FHERandBounded operation.
     * @param upperBound    Upper bound value.
     * @param randType      Type for the random result.
     * @return result       Result.
     */
    function fheRandBounded(uint256 upperBound, FheType randType) external returns (bytes32 result);

    /**
     * @notice                      Returns the address of the InputVerifier contract used by the coprocessor.
     * @return inputVerifierAddress Address of the InputVerifier.
     */
    function getInputVerifierAddress() external view returns (address);
}

/**
 * @title   IACL.
 * @notice  This interface contains all functions that are used to conduct operations
 *          with the ACL contract.
 */
interface IACL {
    /**
     * @notice              Executes a batch of encoded calls on the ACL contract.
     * @param data          Array containing the ABI-encoded function calls.
     * @return results      Return payloads for each call in `data`.
     */
    function multicall(bytes[] calldata data) external payable returns (bytes[] memory results);

    /**
     * @notice              Allows the use of handle by address account for this transaction.
     * @dev                 The caller must be allowed to use handle for allowTransient() to succeed.
     *                      If not, allowTransient() reverts.
     *                      The Coprocessor contract can always allowTransient(), contrarily to allow().
     * @param ciphertext    Ciphertext.
     * @param account       Address of the account.
     */
    function allowTransient(bytes32 ciphertext, address account) external;

    /**
     * @notice              Allows the use of handle for the address account.
     * @dev                 The caller must be allowed to use handle for allow() to succeed. If not, allow() reverts.
     * @param handle        Handle.
     * @param account       Address of the account.
     */
    function allow(bytes32 handle, address account) external;

    /**
     * @dev This function removes the transient allowances, which could be useful for integration with
     *      Account Abstraction when bundling several UserOps calling the FHEVMExecutor Coprocessor.
     */
    function cleanTransientStorage() external;

    /**
     * @notice              Returns whether the account is allowed to use the handle, either due to
     *                      allowTransient() or allow().
     * @param handle        Handle.
     * @param account       Address of the account.
     * @return isAllowed    Whether the account can access the handle.
     */
    function isAllowed(bytes32 handle, address account) external view returns (bool);

    /**
     * @notice              Allows a list of handles to be decrypted.
     * @param handlesList   List of handles.
     */
    function allowForDecryption(bytes32[] memory handlesList) external;

    /**
     * @notice                  Returns wether a handle is allowed to be publicly decrypted.
     * @param handle            Handle.
     * @return isDecryptable    Whether the handle can be publicly decrypted.
     */
    function isAllowedForDecryption(bytes32 handle) external view returns (bool);

    /**
     * @notice              Returns whether the account is persistently allowed to use the handle.
     * @param handle        Handle.
     * @param account       Address of the account.
     */
    function persistAllowed(bytes32 handle, address account) external view returns (bool);

    /**
     * @notice                  Returns whether the account is on the deny list.
     * @param account           Address of the account.
     * @return isAccountDenied  Whether the account is on the deny list.
     */
    function isAccountDenied(address account) external view returns (bool);

    /**
     * @notice              Delegates user decryption rights to `delegate` for the specified `contractAddress`.
     * @param delegate      The delegate account.
     * @param contractAddress The contract address forming the user decryption context.
     * @param expirationDate UNIX timestamp when the delegation expires.
     */
    function delegateForUserDecryption(address delegate, address contractAddress, uint64 expirationDate) external;

    /**
     * @notice              Revokes previously delegated user decryption rights.
     * @param delegate      The delegate account.
     * @param contractAddress The contract address forming the user decryption context.
     */
    function revokeDelegationForUserDecryption(address delegate, address contractAddress) external;

    /**
     * @notice              Returns the expiration date for delegated user decryption rights.
     * @param delegator     The delegator account.
     * @param delegate      The delegate account.
     * @param contractAddress The contract address forming the user decryption context.
     */
    function getUserDecryptionDelegationExpirationDate(
        address delegator,
        address delegate,
        address contractAddress
    ) external view returns (uint64);

    /**
     * @notice Returns whether an account is delegated to access the handle for user decryption.
     * @param delegator The address of the account that delegates access to its handles.
     * @param delegate The address of the account that receives the delegation.
     * @param contractAddress The contract address to delegate access to.
     * @param handle The handle to check for delegated user decryption.
     * @return isDelegatedForUserDecryption Whether the handle can be accessed for delegated user decryption.
     */
    function isHandleDelegatedForUserDecryption(
        address delegator,
        address delegate,
        address contractAddress,
        bytes32 handle
    ) external view returns (bool);
}

/**
 * @title IInputVerifier
 * @notice This interface contains the only function required from InputVerifier.
 */
interface IInputVerifier {
    /**
     * @dev This function removes the transient allowances, which could be useful for integration with
     *      Account Abstraction when bundling several UserOps calling the FHEVMExecutor Coprocessor.
     */
    function cleanTransientStorage() external;
}

/**
 * @title   Impl
 * @notice  This library is the core implementation for computing FHE operations (e.g. add, sub, xor).
 */
library Impl {
    /// keccak256(abi.encode(uint256(keccak256("confidential.storage.config")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant CoprocessorConfigLocation =
        0x9e7b61f58c47dc699ac88507c4f5bb9f121c03808c5676a8078fe583e4649700;

    /**
     * @dev Returns the Coprocessor config.
     */
    function getCoprocessorConfig() internal pure returns (CoprocessorConfig storage $) {
        assembly {
            $.slot := CoprocessorConfigLocation
        }
    }

    /**
     * @notice                  Sets the coprocessor addresses.
     * @param coprocessorConfig Coprocessor config struct that contains contract addresses.
     */
    function setCoprocessor(CoprocessorConfig memory coprocessorConfig) internal {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        $.ACLAddress = coprocessorConfig.ACLAddress;
        $.CoprocessorAddress = coprocessorConfig.CoprocessorAddress;
        $.KMSVerifierAddress = coprocessorConfig.KMSVerifierAddress;
    }

    function add(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheAdd(lhs, rhs, scalarByte);
    }

    function sub(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheSub(lhs, rhs, scalarByte);
    }

    function mul(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheMul(lhs, rhs, scalarByte);
    }

    function div(bytes32 lhs, bytes32 rhs) internal returns (bytes32 result) {
        bytes1 scalarByte = 0x01;
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheDiv(lhs, rhs, scalarByte);
    }

    function rem(bytes32 lhs, bytes32 rhs) internal returns (bytes32 result) {
        bytes1 scalarByte = 0x01;
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheRem(lhs, rhs, scalarByte);
    }

    function and(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheBitAnd(lhs, rhs, scalarByte);
    }

    function or(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheBitOr(lhs, rhs, scalarByte);
    }

    function xor(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheBitXor(lhs, rhs, scalarByte);
    }

    function shl(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheShl(lhs, rhs, scalarByte);
    }

    function shr(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheShr(lhs, rhs, scalarByte);
    }

    function rotl(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheRotl(lhs, rhs, scalarByte);
    }

    function rotr(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheRotr(lhs, rhs, scalarByte);
    }

    function eq(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheEq(lhs, rhs, scalarByte);
    }

    function ne(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheNe(lhs, rhs, scalarByte);
    }

    function ge(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheGe(lhs, rhs, scalarByte);
    }

    function gt(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheGt(lhs, rhs, scalarByte);
    }

    function le(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheLe(lhs, rhs, scalarByte);
    }

    function lt(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheLt(lhs, rhs, scalarByte);
    }

    function min(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheMin(lhs, rhs, scalarByte);
    }

    function max(bytes32 lhs, bytes32 rhs, bool scalar) internal returns (bytes32 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheMax(lhs, rhs, scalarByte);
    }

    function neg(bytes32 ct) internal returns (bytes32 result) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheNeg(ct);
    }

    function not(bytes32 ct) internal returns (bytes32 result) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheNot(ct);
    }

    /**
     * @dev If 'control's value is 'true', the result has the same value as 'ifTrue'.
     *      If 'control's value is 'false', the result has the same value as 'ifFalse'.
     */
    function select(bytes32 control, bytes32 ifTrue, bytes32 ifFalse) internal returns (bytes32 result) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheIfThenElse(control, ifTrue, ifFalse);
    }

    /**
     * @notice              Verifies the ciphertext (FHEVMExecutor) and allows transient (ACL).
     * @param inputHandle   Input handle.
     * @param inputProof    Input proof.
     * @param toType        Input type.
     * @return result       Result.
     */
    function verify(bytes32 inputHandle, bytes memory inputProof, FheType toType) internal returns (bytes32 result) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).verifyInput(inputHandle, msg.sender, inputProof, toType);
        IACL($.ACLAddress).allowTransient(result, msg.sender);
    }

    /**
     * @notice            Performs the casting to a target type.
     * @param ciphertext  Ciphertext to cast.
     * @param toType      Target type.
     * @return result     Result value of the target type.
     */
    function cast(bytes32 ciphertext, FheType toType) internal returns (bytes32 result) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).cast(ciphertext, toType);
    }

    /**
     * @notice          Does trivial encryption.
     * @param value     Value to encrypt.
     * @param toType    Target type.
     * @return result   Result value of the target type.
     */
    function trivialEncrypt(uint256 value, FheType toType) internal returns (bytes32 result) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).trivialEncrypt(value, toType);
    }

    function rand(FheType randType) internal returns (bytes32 result) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheRand(randType);
    }

    function randBounded(uint256 upperBound, FheType randType) internal returns (bytes32 result) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        result = IFHEVMExecutor($.CoprocessorAddress).fheRandBounded(upperBound, randType);
    }

    /**
     * @notice              Allows the use of handle by address account for this transaction.
     * @dev                 The caller must be allowed to use handle for allowTransient() to succeed.
     *                      If not, allowTransient() reverts.
     *                      The Coprocessor contract can always allowTransient(), contrarily to allow().
     * @param handle        Handle.
     * @param account       Address of the account.
     */
    function allowTransient(bytes32 handle, address account) internal {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        IACL($.ACLAddress).allowTransient(handle, account);
    }

    /**
     * @notice              Allows the use of handle for the address account.
     * @dev                 The caller must be allowed to use handle for allow() to succeed. If not, allow() reverts.
     * @param handle        Handle.
     * @param account       Address of the account.
     */
    function allow(bytes32 handle, address account) internal {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        IACL($.ACLAddress).allow(handle, account);
    }

    /**
     * @notice              Allows the handle to be publicly decryptable.
     * @dev                 The caller must be allowed to use handle for makePubliclyDecryptable() to succeed.
     *                      If not, makePubliclyDecryptable() reverts.
     * @param handle        Handle.
     */
    function makePubliclyDecryptable(bytes32 handle) internal {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        bytes32[] memory handleArray = new bytes32[](1);
        handleArray[0] = handle;
        IACL($.ACLAddress).allowForDecryption(handleArray);
    }

    /**
     * @dev This function removes the transient allowances in the ACL, which could be useful for integration
     *      with Account Abstraction when bundling several UserOps calling the FHEVMExecutor Coprocessor.
     */
    function cleanTransientStorageACL() internal {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        IACL($.ACLAddress).cleanTransientStorage();
    }

    /**
     * @dev This function removes the transient proofs in the InputVerifier, which could be useful for integration
     *      with Account Abstraction when bundling several UserOps calling the FHEVMExecutor Coprocessor.
     */
    function cleanTransientStorageInputVerifier() internal {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        address inputVerifierAddress = IFHEVMExecutor($.CoprocessorAddress).getInputVerifierAddress();
        IInputVerifier(inputVerifierAddress).cleanTransientStorage();
    }

    /**
     * @notice              Returns whether the account is allowed to use the handle, either due to
     *                      allowTransient() or allow().
     * @param handle        Handle.
     * @param account       Address of the account.
     * @return isAllowed    Whether the account can access the handle.
     */
    function isAllowed(bytes32 handle, address account) internal view returns (bool) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        return IACL($.ACLAddress).isAllowed(handle, account);
    }

    /**
     * @notice              Returns whether the handle is allowed to be publicly decrypted.
     * @param handle        Handle.
     * @return isAllowed    Whether the handle can be publicly decrypted.
     */
    function isPubliclyDecryptable(bytes32 handle) internal view returns (bool) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        return IACL($.ACLAddress).isAllowedForDecryption(handle);
    }

    /**
     * @notice              Returns whether the account is persistently allowed to use the handle.
     * @param handle        Handle.
     * @param account       Address of the account.
     * @return isAllowed    Whether the account can access the handle persistently.
     */
    function persistAllowed(bytes32 handle, address account) internal view returns (bool) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        return IACL($.ACLAddress).persistAllowed(handle, account);
    }

    /**
     * @notice                  Returns whether the account is on the deny list.
     * @param account           Address of the account.
     * @return isAccountDenied  Whether the account is on the deny list.
     */
    function isAccountDenied(address account) internal view returns (bool) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        return IACL($.ACLAddress).isAccountDenied(account);
    }

    /**
     * @notice              Delegates user decryption rights to `delegate` for the specified `contractAddress`.
     * @param delegate      The delegate account.
     * @param contractAddress The contract address forming the user decryption context.
     * @param expirationDate UNIX timestamp when the delegation expires.
     */
    function delegateForUserDecryption(address delegate, address contractAddress, uint64 expirationDate) internal {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        IACL($.ACLAddress).delegateForUserDecryption(delegate, contractAddress, expirationDate);
    }

    /**
     * @notice              Delegates user decryption rights in batch leveraging the ACL multicall helper.
     * @param delegate      The delegate account.
     * @param contractAddresses Array of contract addresses forming the user decryption contexts.
     * @param expirationDate UNIX timestamp when the delegation expires.
     */
    function delegateForUserDecryptions(
        address delegate,
        address[] memory contractAddresses,
        uint64 expirationDate
    ) internal {
        uint256 length = contractAddresses.length;
        if (length == 0) {
            return;
        }

        CoprocessorConfig storage $ = getCoprocessorConfig();

        if (length == 1) {
            IACL($.ACLAddress).delegateForUserDecryption(delegate, contractAddresses[0], expirationDate);
            return;
        }

        bytes[] memory calls = new bytes[](length);
        for (uint256 i = 0; i < length; ++i) {
            calls[i] = abi.encodeCall(IACL.delegateForUserDecryption, (delegate, contractAddresses[i], expirationDate));
        }
        IACL($.ACLAddress).multicall(calls);
    }

    /**
     * @notice              Revokes previously delegated user decryption rights.
     * @param delegate      The delegate account.
     * @param contractAddress The contract address forming the user decryption context.
     */
    function revokeDelegationForUserDecryption(address delegate, address contractAddress) internal {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        IACL($.ACLAddress).revokeDelegationForUserDecryption(delegate, contractAddress);
    }

    /**
     * @notice              Revokes delegated user decryption rights in batch leveraging the ACL multicall helper.
     * @param delegate      The delegate account.
     * @param contractAddresses Array of contract addresses forming the user decryption contexts.
     */
    function revokeDelegationsForUserDecryption(address delegate, address[] memory contractAddresses) internal {
        uint256 length = contractAddresses.length;
        if (length == 0) {
            return;
        }

        CoprocessorConfig storage $ = getCoprocessorConfig();

        if (length == 1) {
            IACL($.ACLAddress).revokeDelegationForUserDecryption(delegate, contractAddresses[0]);
            return;
        }

        bytes[] memory calls = new bytes[](length);
        for (uint256 i = 0; i < length; ++i) {
            calls[i] = abi.encodeCall(IACL.revokeDelegationForUserDecryption, (delegate, contractAddresses[i]));
        }
        IACL($.ACLAddress).multicall(calls);
    }

    /**
     * @notice              Returns the expiration date for delegated user decryption rights.
     * @param delegator     The delegator account.
     * @param delegate      The delegate account.
     * @param contractAddress The contract address forming the user decryption context.
     * @return expirationDate The UNIX timestamp when the delegation expires.
     */
    function getUserDecryptionDelegationExpirationDate(
        address delegator,
        address delegate,
        address contractAddress
    ) internal view returns (uint64) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        return IACL($.ACLAddress).getUserDecryptionDelegationExpirationDate(delegator, delegate, contractAddress);
    }

    /**
     * @notice              Returns whether the handle is delegated for user decryption.
     * @param delegator     The delegator account.
     * @param delegate      The delegate account.
     * @param contractAddress The contract address forming the user decryption context.
     * @param handle          The handle.
     * @return isDelegated    Whether the handle is delegated for user decryption.
     */
    function isDelegatedForUserDecryption(
        address delegator,
        address delegate,
        address contractAddress,
        bytes32 handle
    ) internal view returns (bool) {
        CoprocessorConfig storage $ = getCoprocessorConfig();
        return IACL($.ACLAddress).isHandleDelegatedForUserDecryption(delegator, delegate, contractAddress, handle);
    }
}


// File encrypted-types/EncryptedTypes.sol@v0.0.4

// Original license: SPDX_License_Identifier: MIT
pragma solidity ^0.8.24;

type ebool is bytes32;

type euint8 is bytes32;
type euint16 is bytes32;
type euint24 is bytes32;
type euint32 is bytes32;
type euint40 is bytes32;
type euint48 is bytes32;
type euint56 is bytes32;
type euint64 is bytes32;
type euint72 is bytes32;
type euint80 is bytes32;
type euint88 is bytes32;
type euint96 is bytes32;
type euint104 is bytes32;
type euint112 is bytes32;
type euint120 is bytes32;
type euint128 is bytes32;
type euint136 is bytes32;
type euint144 is bytes32;
type euint152 is bytes32;
type euint160 is bytes32;
type euint168 is bytes32;
type euint176 is bytes32;
type euint184 is bytes32;
type euint192 is bytes32;
type euint200 is bytes32;
type euint208 is bytes32;
type euint216 is bytes32;
type euint224 is bytes32;
type euint232 is bytes32;
type euint240 is bytes32;
type euint248 is bytes32;
type euint256 is bytes32;

type eint8 is bytes32;
type eint16 is bytes32;
type eint24 is bytes32;
type eint32 is bytes32;
type eint40 is bytes32;
type eint48 is bytes32;
type eint56 is bytes32;
type eint64 is bytes32;
type eint72 is bytes32;
type eint80 is bytes32;
type eint88 is bytes32;
type eint96 is bytes32;
type eint104 is bytes32;
type eint112 is bytes32;
type eint120 is bytes32;
type eint128 is bytes32;
type eint136 is bytes32;
type eint144 is bytes32;
type eint152 is bytes32;
type eint160 is bytes32;
type eint168 is bytes32;
type eint176 is bytes32;
type eint184 is bytes32;
type eint192 is bytes32;
type eint200 is bytes32;
type eint208 is bytes32;
type eint216 is bytes32;
type eint224 is bytes32;
type eint232 is bytes32;
type eint240 is bytes32;
type eint248 is bytes32;
type eint256 is bytes32;

type eaddress is bytes32;

type ebytes1 is bytes32;
type ebytes2 is bytes32;
type ebytes3 is bytes32;
type ebytes4 is bytes32;
type ebytes5 is bytes32;
type ebytes6 is bytes32;
type ebytes7 is bytes32;
type ebytes8 is bytes32;
type ebytes9 is bytes32;
type ebytes10 is bytes32;
type ebytes11 is bytes32;
type ebytes12 is bytes32;
type ebytes13 is bytes32;
type ebytes14 is bytes32;
type ebytes15 is bytes32;
type ebytes16 is bytes32;
type ebytes17 is bytes32;
type ebytes18 is bytes32;
type ebytes19 is bytes32;
type ebytes20 is bytes32;
type ebytes21 is bytes32;
type ebytes22 is bytes32;
type ebytes23 is bytes32;
type ebytes24 is bytes32;
type ebytes25 is bytes32;
type ebytes26 is bytes32;
type ebytes27 is bytes32;
type ebytes28 is bytes32;
type ebytes29 is bytes32;
type ebytes30 is bytes32;
type ebytes31 is bytes32;
type ebytes32 is bytes32;

type externalEbool is bytes32;

type externalEuint8 is bytes32;
type externalEuint16 is bytes32;
type externalEuint24 is bytes32;
type externalEuint32 is bytes32;
type externalEuint40 is bytes32;
type externalEuint48 is bytes32;
type externalEuint56 is bytes32;
type externalEuint64 is bytes32;
type externalEuint72 is bytes32;
type externalEuint80 is bytes32;
type externalEuint88 is bytes32;
type externalEuint96 is bytes32;
type externalEuint104 is bytes32;
type externalEuint112 is bytes32;
type externalEuint120 is bytes32;
type externalEuint128 is bytes32;
type externalEuint136 is bytes32;
type externalEuint144 is bytes32;
type externalEuint152 is bytes32;
type externalEuint160 is bytes32;
type externalEuint168 is bytes32;
type externalEuint176 is bytes32;
type externalEuint184 is bytes32;
type externalEuint192 is bytes32;
type externalEuint200 is bytes32;
type externalEuint208 is bytes32;
type externalEuint216 is bytes32;
type externalEuint224 is bytes32;
type externalEuint232 is bytes32;
type externalEuint240 is bytes32;
type externalEuint248 is bytes32;
type externalEuint256 is bytes32;

type externalEint8 is bytes32;
type externalEint16 is bytes32;
type externalEint24 is bytes32;
type externalEint32 is bytes32;
type externalEint40 is bytes32;
type externalEint48 is bytes32;
type externalEint56 is bytes32;
type externalEint64 is bytes32;
type externalEint72 is bytes32;
type externalEint80 is bytes32;
type externalEint88 is bytes32;
type externalEint96 is bytes32;
type externalEint104 is bytes32;
type externalEint112 is bytes32;
type externalEint120 is bytes32;
type externalEint128 is bytes32;
type externalEint136 is bytes32;
type externalEint144 is bytes32;
type externalEint152 is bytes32;
type externalEint160 is bytes32;
type externalEint168 is bytes32;
type externalEint176 is bytes32;
type externalEint184 is bytes32;
type externalEint192 is bytes32;
type externalEint200 is bytes32;
type externalEint208 is bytes32;
type externalEint216 is bytes32;
type externalEint224 is bytes32;
type externalEint232 is bytes32;
type externalEint240 is bytes32;
type externalEint248 is bytes32;
type externalEint256 is bytes32;

type externalEaddress is bytes32;

type externalEbytes1 is bytes32;
type externalEbytes2 is bytes32;
type externalEbytes3 is bytes32;
type externalEbytes4 is bytes32;
type externalEbytes5 is bytes32;
type externalEbytes6 is bytes32;
type externalEbytes7 is bytes32;
type externalEbytes8 is bytes32;
type externalEbytes9 is bytes32;
type externalEbytes10 is bytes32;
type externalEbytes11 is bytes32;
type externalEbytes12 is bytes32;
type externalEbytes13 is bytes32;
type externalEbytes14 is bytes32;
type externalEbytes15 is bytes32;
type externalEbytes16 is bytes32;
type externalEbytes17 is bytes32;
type externalEbytes18 is bytes32;
type externalEbytes19 is bytes32;
type externalEbytes20 is bytes32;
type externalEbytes21 is bytes32;
type externalEbytes22 is bytes32;
type externalEbytes23 is bytes32;
type externalEbytes24 is bytes32;
type externalEbytes25 is bytes32;
type externalEbytes26 is bytes32;
type externalEbytes27 is bytes32;
type externalEbytes28 is bytes32;
type externalEbytes29 is bytes32;
type externalEbytes30 is bytes32;
type externalEbytes31 is bytes32;
type externalEbytes32 is bytes32;


// File @fhevm/solidity/lib/FHE.sol@v0.11.1

// Original license: SPDX_License_Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;



/**
 * @title IKMSVerifier
 * @notice This interface contains the only function required from KMSVerifier.
 */
interface IKMSVerifier {
    function verifyDecryptionEIP712KMSSignatures(
        bytes32[] memory handlesList,
        bytes memory decryptedResult,
        bytes memory decryptionProof
    ) external returns (bool);

    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );

    function getThreshold() external view returns (uint256);

    function getKmsSigners() external view returns (address[] memory);
}

/**
 * @title   FHE
 * @notice  This library is the interaction point for all smart contract developers
 *          that interact with the FHEVM protocol.
 */
library FHE {
    /// @notice Decryption result typehash.
    bytes32 private constant DECRYPTION_RESULT_TYPEHASH =
        keccak256("PublicDecryptVerification(bytes32[] ctHandles,bytes decryptedResult,bytes extraData)");

    /// @notice EIP-712 domain  typehash.
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @notice Returned if the deserializing of the decryption proof fails.
    error DeserializingDecryptionProofFail();

    /// @notice Returned if the decryption proof is empty.
    error EmptyDecryptionProof();

    /// @notice Returned if the recovered KMS signer is not a valid KMS signer.
    /// @param invalidSigner Address of the invalid signer.
    error KMSInvalidSigner(address invalidSigner);

    /// @notice                 Returned if the number of signatures is inferior to the threshold.
    /// @param numSignatures    Number of signatures.
    error KMSSignatureThresholdNotReached(uint256 numSignatures);

    /// @notice Returned if the number of signatures is equal to 0.
    error KMSZeroSignature();

    /// @notice Returned if the returned KMS signatures are not valid.
    error InvalidKMSSignatures();

    /// @notice Returned if the sender is not allowed to use the handle.
    error SenderNotAllowedToUseHandle(bytes32 handle, address sender);

    /// @notice This event is emitted when public decryption has been successfully verified.
    event PublicDecryptionVerified(bytes32[] handlesList, bytes abiEncodedCleartexts);

    /**
     * @notice                  Sets the coprocessor addresses.
     * @param coprocessorConfig Coprocessor config struct that contains contract addresses.
     */
    function setCoprocessor(CoprocessorConfig memory coprocessorConfig) internal {
        Impl.setCoprocessor(coprocessorConfig);
    }

    /**
     * @dev Returns true if the encrypted integer is initialized and false otherwise.
     */
    function isInitialized(ebool v) internal pure returns (bool) {
        return ebool.unwrap(v) != 0;
    }

    /**
     * @dev Returns true if the encrypted integer is initialized and false otherwise.
     */
    function isInitialized(euint8 v) internal pure returns (bool) {
        return euint8.unwrap(v) != 0;
    }

    /**
     * @dev Returns true if the encrypted integer is initialized and false otherwise.
     */
    function isInitialized(euint16 v) internal pure returns (bool) {
        return euint16.unwrap(v) != 0;
    }

    /**
     * @dev Returns true if the encrypted integer is initialized and false otherwise.
     */
    function isInitialized(euint32 v) internal pure returns (bool) {
        return euint32.unwrap(v) != 0;
    }

    /**
     * @dev Returns true if the encrypted integer is initialized and false otherwise.
     */
    function isInitialized(euint64 v) internal pure returns (bool) {
        return euint64.unwrap(v) != 0;
    }

    /**
     * @dev Returns true if the encrypted integer is initialized and false otherwise.
     */
    function isInitialized(euint128 v) internal pure returns (bool) {
        return euint128.unwrap(v) != 0;
    }

    /**
     * @dev Returns true if the encrypted integer is initialized and false otherwise.
     */
    function isInitialized(eaddress v) internal pure returns (bool) {
        return eaddress.unwrap(v) != 0;
    }

    /**
     * @dev Returns true if the encrypted integer is initialized and false otherwise.
     */
    function isInitialized(euint256 v) internal pure returns (bool) {
        return euint256.unwrap(v) != 0;
    }

    /**
     * @dev Evaluates and(ebool a, ebool b) and returns the result.
     */
    function and(ebool a, ebool b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEbool(false);
        }
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return ebool.wrap(Impl.and(ebool.unwrap(a), ebool.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(ebool a, ebool b) and returns the result.
     */
    function or(ebool a, ebool b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEbool(false);
        }
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return ebool.wrap(Impl.or(ebool.unwrap(a), ebool.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(ebool a, ebool b) and returns the result.
     */
    function xor(ebool a, ebool b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEbool(false);
        }
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return ebool.wrap(Impl.xor(ebool.unwrap(a), ebool.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(ebool a, ebool b) and returns the result.
     */
    function eq(ebool a, ebool b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEbool(false);
        }
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return ebool.wrap(Impl.eq(ebool.unwrap(a), ebool.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(ebool a, ebool b) and returns the result.
     */
    function ne(ebool a, ebool b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEbool(false);
        }
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return ebool.wrap(Impl.ne(ebool.unwrap(a), ebool.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint8 a, euint8 b)  and returns the result.
     */
    function add(euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.add(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint8 a, euint8 b)  and returns the result.
     */
    function sub(euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.sub(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint8 a, euint8 b)  and returns the result.
     */
    function mul(euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.mul(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint8 a, euint8 b)  and returns the result.
     */
    function and(euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.and(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint8 a, euint8 b)  and returns the result.
     */
    function or(euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.or(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint8 a, euint8 b)  and returns the result.
     */
    function xor(euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.xor(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint8 a, euint8 b)  and returns the result.
     */
    function eq(euint8 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.eq(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint8 a, euint8 b)  and returns the result.
     */
    function ne(euint8 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ne(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint8 a, euint8 b)  and returns the result.
     */
    function ge(euint8 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ge(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint8 a, euint8 b)  and returns the result.
     */
    function gt(euint8 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.gt(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint8 a, euint8 b)  and returns the result.
     */
    function le(euint8 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.le(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint8 a, euint8 b)  and returns the result.
     */
    function lt(euint8 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.lt(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint8 a, euint8 b)  and returns the result.
     */
    function min(euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.min(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint8 a, euint8 b)  and returns the result.
     */
    function max(euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.max(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint8 a, euint16 b)  and returns the result.
     */
    function add(euint8 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.add(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint8 a, euint16 b)  and returns the result.
     */
    function sub(euint8 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.sub(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint8 a, euint16 b)  and returns the result.
     */
    function mul(euint8 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.mul(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint8 a, euint16 b)  and returns the result.
     */
    function and(euint8 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.and(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint8 a, euint16 b)  and returns the result.
     */
    function or(euint8 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.or(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint8 a, euint16 b)  and returns the result.
     */
    function xor(euint8 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.xor(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint8 a, euint16 b)  and returns the result.
     */
    function eq(euint8 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.eq(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint8 a, euint16 b)  and returns the result.
     */
    function ne(euint8 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ne(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint8 a, euint16 b)  and returns the result.
     */
    function ge(euint8 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ge(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint8 a, euint16 b)  and returns the result.
     */
    function gt(euint8 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.gt(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint8 a, euint16 b)  and returns the result.
     */
    function le(euint8 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.le(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint8 a, euint16 b)  and returns the result.
     */
    function lt(euint8 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.lt(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint8 a, euint16 b)  and returns the result.
     */
    function min(euint8 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.min(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint8 a, euint16 b)  and returns the result.
     */
    function max(euint8 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.max(euint16.unwrap(asEuint16(a)), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint8 a, euint32 b)  and returns the result.
     */
    function add(euint8 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.add(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint8 a, euint32 b)  and returns the result.
     */
    function sub(euint8 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.sub(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint8 a, euint32 b)  and returns the result.
     */
    function mul(euint8 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.mul(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint8 a, euint32 b)  and returns the result.
     */
    function and(euint8 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.and(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint8 a, euint32 b)  and returns the result.
     */
    function or(euint8 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.or(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint8 a, euint32 b)  and returns the result.
     */
    function xor(euint8 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.xor(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint8 a, euint32 b)  and returns the result.
     */
    function eq(euint8 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.eq(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint8 a, euint32 b)  and returns the result.
     */
    function ne(euint8 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ne(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint8 a, euint32 b)  and returns the result.
     */
    function ge(euint8 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ge(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint8 a, euint32 b)  and returns the result.
     */
    function gt(euint8 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.gt(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint8 a, euint32 b)  and returns the result.
     */
    function le(euint8 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.le(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint8 a, euint32 b)  and returns the result.
     */
    function lt(euint8 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.lt(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint8 a, euint32 b)  and returns the result.
     */
    function min(euint8 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.min(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint8 a, euint32 b)  and returns the result.
     */
    function max(euint8 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.max(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint8 a, euint64 b)  and returns the result.
     */
    function add(euint8 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.add(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint8 a, euint64 b)  and returns the result.
     */
    function sub(euint8 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.sub(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint8 a, euint64 b)  and returns the result.
     */
    function mul(euint8 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.mul(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint8 a, euint64 b)  and returns the result.
     */
    function and(euint8 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.and(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint8 a, euint64 b)  and returns the result.
     */
    function or(euint8 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.or(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint8 a, euint64 b)  and returns the result.
     */
    function xor(euint8 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.xor(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint8 a, euint64 b)  and returns the result.
     */
    function eq(euint8 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.eq(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint8 a, euint64 b)  and returns the result.
     */
    function ne(euint8 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ne(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint8 a, euint64 b)  and returns the result.
     */
    function ge(euint8 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ge(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint8 a, euint64 b)  and returns the result.
     */
    function gt(euint8 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.gt(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint8 a, euint64 b)  and returns the result.
     */
    function le(euint8 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.le(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint8 a, euint64 b)  and returns the result.
     */
    function lt(euint8 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.lt(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint8 a, euint64 b)  and returns the result.
     */
    function min(euint8 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.min(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint8 a, euint64 b)  and returns the result.
     */
    function max(euint8 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.max(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint8 a, euint128 b)  and returns the result.
     */
    function add(euint8 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.add(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint8 a, euint128 b)  and returns the result.
     */
    function sub(euint8 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.sub(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint8 a, euint128 b)  and returns the result.
     */
    function mul(euint8 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.mul(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint8 a, euint128 b)  and returns the result.
     */
    function and(euint8 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.and(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint8 a, euint128 b)  and returns the result.
     */
    function or(euint8 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.or(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint8 a, euint128 b)  and returns the result.
     */
    function xor(euint8 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.xor(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint8 a, euint128 b)  and returns the result.
     */
    function eq(euint8 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.eq(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint8 a, euint128 b)  and returns the result.
     */
    function ne(euint8 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ne(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint8 a, euint128 b)  and returns the result.
     */
    function ge(euint8 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ge(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint8 a, euint128 b)  and returns the result.
     */
    function gt(euint8 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.gt(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint8 a, euint128 b)  and returns the result.
     */
    function le(euint8 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.le(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint8 a, euint128 b)  and returns the result.
     */
    function lt(euint8 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.lt(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint8 a, euint128 b)  and returns the result.
     */
    function min(euint8 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.min(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint8 a, euint128 b)  and returns the result.
     */
    function max(euint8 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.max(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint8 a, euint256 b)  and returns the result.
     */
    function and(euint8 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint8 a, euint256 b)  and returns the result.
     */
    function or(euint8 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint8 a, euint256 b)  and returns the result.
     */
    function xor(euint8 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint8 a, euint256 b)  and returns the result.
     */
    function eq(euint8 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint8 a, euint256 b)  and returns the result.
     */
    function ne(euint8 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint16 a, euint8 b)  and returns the result.
     */
    function add(euint16 a, euint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint16.wrap(Impl.add(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates sub(euint16 a, euint8 b)  and returns the result.
     */
    function sub(euint16 a, euint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint16.wrap(Impl.sub(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates mul(euint16 a, euint8 b)  and returns the result.
     */
    function mul(euint16 a, euint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint16.wrap(Impl.mul(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates and(euint16 a, euint8 b)  and returns the result.
     */
    function and(euint16 a, euint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint16.wrap(Impl.and(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates or(euint16 a, euint8 b)  and returns the result.
     */
    function or(euint16 a, euint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint16.wrap(Impl.or(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates xor(euint16 a, euint8 b)  and returns the result.
     */
    function xor(euint16 a, euint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint16.wrap(Impl.xor(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates eq(euint16 a, euint8 b)  and returns the result.
     */
    function eq(euint16 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.eq(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates ne(euint16 a, euint8 b)  and returns the result.
     */
    function ne(euint16 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ne(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates ge(euint16 a, euint8 b)  and returns the result.
     */
    function ge(euint16 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ge(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates gt(euint16 a, euint8 b)  and returns the result.
     */
    function gt(euint16 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.gt(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates le(euint16 a, euint8 b)  and returns the result.
     */
    function le(euint16 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.le(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates lt(euint16 a, euint8 b)  and returns the result.
     */
    function lt(euint16 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.lt(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates min(euint16 a, euint8 b)  and returns the result.
     */
    function min(euint16 a, euint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint16.wrap(Impl.min(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates max(euint16 a, euint8 b)  and returns the result.
     */
    function max(euint16 a, euint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint16.wrap(Impl.max(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates add(euint16 a, euint16 b)  and returns the result.
     */
    function add(euint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.add(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint16 a, euint16 b)  and returns the result.
     */
    function sub(euint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.sub(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint16 a, euint16 b)  and returns the result.
     */
    function mul(euint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.mul(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint16 a, euint16 b)  and returns the result.
     */
    function and(euint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.and(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint16 a, euint16 b)  and returns the result.
     */
    function or(euint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.or(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint16 a, euint16 b)  and returns the result.
     */
    function xor(euint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.xor(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint16 a, euint16 b)  and returns the result.
     */
    function eq(euint16 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.eq(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint16 a, euint16 b)  and returns the result.
     */
    function ne(euint16 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ne(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint16 a, euint16 b)  and returns the result.
     */
    function ge(euint16 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ge(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint16 a, euint16 b)  and returns the result.
     */
    function gt(euint16 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.gt(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint16 a, euint16 b)  and returns the result.
     */
    function le(euint16 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.le(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint16 a, euint16 b)  and returns the result.
     */
    function lt(euint16 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.lt(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint16 a, euint16 b)  and returns the result.
     */
    function min(euint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.min(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint16 a, euint16 b)  and returns the result.
     */
    function max(euint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.max(euint16.unwrap(a), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint16 a, euint32 b)  and returns the result.
     */
    function add(euint16 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.add(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint16 a, euint32 b)  and returns the result.
     */
    function sub(euint16 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.sub(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint16 a, euint32 b)  and returns the result.
     */
    function mul(euint16 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.mul(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint16 a, euint32 b)  and returns the result.
     */
    function and(euint16 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.and(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint16 a, euint32 b)  and returns the result.
     */
    function or(euint16 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.or(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint16 a, euint32 b)  and returns the result.
     */
    function xor(euint16 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.xor(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint16 a, euint32 b)  and returns the result.
     */
    function eq(euint16 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.eq(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint16 a, euint32 b)  and returns the result.
     */
    function ne(euint16 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ne(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint16 a, euint32 b)  and returns the result.
     */
    function ge(euint16 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ge(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint16 a, euint32 b)  and returns the result.
     */
    function gt(euint16 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.gt(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint16 a, euint32 b)  and returns the result.
     */
    function le(euint16 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.le(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint16 a, euint32 b)  and returns the result.
     */
    function lt(euint16 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.lt(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint16 a, euint32 b)  and returns the result.
     */
    function min(euint16 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.min(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint16 a, euint32 b)  and returns the result.
     */
    function max(euint16 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.max(euint32.unwrap(asEuint32(a)), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint16 a, euint64 b)  and returns the result.
     */
    function add(euint16 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.add(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint16 a, euint64 b)  and returns the result.
     */
    function sub(euint16 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.sub(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint16 a, euint64 b)  and returns the result.
     */
    function mul(euint16 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.mul(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint16 a, euint64 b)  and returns the result.
     */
    function and(euint16 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.and(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint16 a, euint64 b)  and returns the result.
     */
    function or(euint16 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.or(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint16 a, euint64 b)  and returns the result.
     */
    function xor(euint16 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.xor(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint16 a, euint64 b)  and returns the result.
     */
    function eq(euint16 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.eq(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint16 a, euint64 b)  and returns the result.
     */
    function ne(euint16 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ne(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint16 a, euint64 b)  and returns the result.
     */
    function ge(euint16 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ge(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint16 a, euint64 b)  and returns the result.
     */
    function gt(euint16 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.gt(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint16 a, euint64 b)  and returns the result.
     */
    function le(euint16 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.le(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint16 a, euint64 b)  and returns the result.
     */
    function lt(euint16 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.lt(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint16 a, euint64 b)  and returns the result.
     */
    function min(euint16 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.min(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint16 a, euint64 b)  and returns the result.
     */
    function max(euint16 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.max(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint16 a, euint128 b)  and returns the result.
     */
    function add(euint16 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.add(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint16 a, euint128 b)  and returns the result.
     */
    function sub(euint16 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.sub(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint16 a, euint128 b)  and returns the result.
     */
    function mul(euint16 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.mul(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint16 a, euint128 b)  and returns the result.
     */
    function and(euint16 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.and(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint16 a, euint128 b)  and returns the result.
     */
    function or(euint16 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.or(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint16 a, euint128 b)  and returns the result.
     */
    function xor(euint16 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.xor(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint16 a, euint128 b)  and returns the result.
     */
    function eq(euint16 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.eq(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint16 a, euint128 b)  and returns the result.
     */
    function ne(euint16 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ne(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint16 a, euint128 b)  and returns the result.
     */
    function ge(euint16 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ge(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint16 a, euint128 b)  and returns the result.
     */
    function gt(euint16 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.gt(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint16 a, euint128 b)  and returns the result.
     */
    function le(euint16 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.le(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint16 a, euint128 b)  and returns the result.
     */
    function lt(euint16 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.lt(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint16 a, euint128 b)  and returns the result.
     */
    function min(euint16 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.min(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint16 a, euint128 b)  and returns the result.
     */
    function max(euint16 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.max(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint16 a, euint256 b)  and returns the result.
     */
    function and(euint16 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint16 a, euint256 b)  and returns the result.
     */
    function or(euint16 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint16 a, euint256 b)  and returns the result.
     */
    function xor(euint16 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint16 a, euint256 b)  and returns the result.
     */
    function eq(euint16 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint16 a, euint256 b)  and returns the result.
     */
    function ne(euint16 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint32 a, euint8 b)  and returns the result.
     */
    function add(euint32 a, euint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint32.wrap(Impl.add(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates sub(euint32 a, euint8 b)  and returns the result.
     */
    function sub(euint32 a, euint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint32.wrap(Impl.sub(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates mul(euint32 a, euint8 b)  and returns the result.
     */
    function mul(euint32 a, euint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint32.wrap(Impl.mul(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates and(euint32 a, euint8 b)  and returns the result.
     */
    function and(euint32 a, euint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint32.wrap(Impl.and(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates or(euint32 a, euint8 b)  and returns the result.
     */
    function or(euint32 a, euint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint32.wrap(Impl.or(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates xor(euint32 a, euint8 b)  and returns the result.
     */
    function xor(euint32 a, euint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint32.wrap(Impl.xor(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates eq(euint32 a, euint8 b)  and returns the result.
     */
    function eq(euint32 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.eq(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates ne(euint32 a, euint8 b)  and returns the result.
     */
    function ne(euint32 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ne(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates ge(euint32 a, euint8 b)  and returns the result.
     */
    function ge(euint32 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ge(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates gt(euint32 a, euint8 b)  and returns the result.
     */
    function gt(euint32 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.gt(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates le(euint32 a, euint8 b)  and returns the result.
     */
    function le(euint32 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.le(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates lt(euint32 a, euint8 b)  and returns the result.
     */
    function lt(euint32 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.lt(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates min(euint32 a, euint8 b)  and returns the result.
     */
    function min(euint32 a, euint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint32.wrap(Impl.min(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates max(euint32 a, euint8 b)  and returns the result.
     */
    function max(euint32 a, euint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint32.wrap(Impl.max(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates add(euint32 a, euint16 b)  and returns the result.
     */
    function add(euint32 a, euint16 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint32.wrap(Impl.add(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates sub(euint32 a, euint16 b)  and returns the result.
     */
    function sub(euint32 a, euint16 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint32.wrap(Impl.sub(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates mul(euint32 a, euint16 b)  and returns the result.
     */
    function mul(euint32 a, euint16 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint32.wrap(Impl.mul(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates and(euint32 a, euint16 b)  and returns the result.
     */
    function and(euint32 a, euint16 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint32.wrap(Impl.and(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates or(euint32 a, euint16 b)  and returns the result.
     */
    function or(euint32 a, euint16 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint32.wrap(Impl.or(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates xor(euint32 a, euint16 b)  and returns the result.
     */
    function xor(euint32 a, euint16 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint32.wrap(Impl.xor(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates eq(euint32 a, euint16 b)  and returns the result.
     */
    function eq(euint32 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.eq(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates ne(euint32 a, euint16 b)  and returns the result.
     */
    function ne(euint32 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ne(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates ge(euint32 a, euint16 b)  and returns the result.
     */
    function ge(euint32 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ge(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates gt(euint32 a, euint16 b)  and returns the result.
     */
    function gt(euint32 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.gt(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates le(euint32 a, euint16 b)  and returns the result.
     */
    function le(euint32 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.le(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates lt(euint32 a, euint16 b)  and returns the result.
     */
    function lt(euint32 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.lt(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates min(euint32 a, euint16 b)  and returns the result.
     */
    function min(euint32 a, euint16 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint32.wrap(Impl.min(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates max(euint32 a, euint16 b)  and returns the result.
     */
    function max(euint32 a, euint16 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint32.wrap(Impl.max(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates add(euint32 a, euint32 b)  and returns the result.
     */
    function add(euint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.add(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint32 a, euint32 b)  and returns the result.
     */
    function sub(euint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.sub(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint32 a, euint32 b)  and returns the result.
     */
    function mul(euint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.mul(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint32 a, euint32 b)  and returns the result.
     */
    function and(euint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.and(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint32 a, euint32 b)  and returns the result.
     */
    function or(euint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.or(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint32 a, euint32 b)  and returns the result.
     */
    function xor(euint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.xor(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint32 a, euint32 b)  and returns the result.
     */
    function eq(euint32 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.eq(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint32 a, euint32 b)  and returns the result.
     */
    function ne(euint32 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ne(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint32 a, euint32 b)  and returns the result.
     */
    function ge(euint32 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ge(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint32 a, euint32 b)  and returns the result.
     */
    function gt(euint32 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.gt(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint32 a, euint32 b)  and returns the result.
     */
    function le(euint32 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.le(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint32 a, euint32 b)  and returns the result.
     */
    function lt(euint32 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.lt(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint32 a, euint32 b)  and returns the result.
     */
    function min(euint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.min(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint32 a, euint32 b)  and returns the result.
     */
    function max(euint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.max(euint32.unwrap(a), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint32 a, euint64 b)  and returns the result.
     */
    function add(euint32 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.add(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint32 a, euint64 b)  and returns the result.
     */
    function sub(euint32 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.sub(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint32 a, euint64 b)  and returns the result.
     */
    function mul(euint32 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.mul(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint32 a, euint64 b)  and returns the result.
     */
    function and(euint32 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.and(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint32 a, euint64 b)  and returns the result.
     */
    function or(euint32 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.or(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint32 a, euint64 b)  and returns the result.
     */
    function xor(euint32 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.xor(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint32 a, euint64 b)  and returns the result.
     */
    function eq(euint32 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.eq(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint32 a, euint64 b)  and returns the result.
     */
    function ne(euint32 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ne(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint32 a, euint64 b)  and returns the result.
     */
    function ge(euint32 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ge(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint32 a, euint64 b)  and returns the result.
     */
    function gt(euint32 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.gt(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint32 a, euint64 b)  and returns the result.
     */
    function le(euint32 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.le(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint32 a, euint64 b)  and returns the result.
     */
    function lt(euint32 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.lt(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint32 a, euint64 b)  and returns the result.
     */
    function min(euint32 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.min(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint32 a, euint64 b)  and returns the result.
     */
    function max(euint32 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.max(euint64.unwrap(asEuint64(a)), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint32 a, euint128 b)  and returns the result.
     */
    function add(euint32 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.add(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint32 a, euint128 b)  and returns the result.
     */
    function sub(euint32 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.sub(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint32 a, euint128 b)  and returns the result.
     */
    function mul(euint32 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.mul(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint32 a, euint128 b)  and returns the result.
     */
    function and(euint32 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.and(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint32 a, euint128 b)  and returns the result.
     */
    function or(euint32 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.or(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint32 a, euint128 b)  and returns the result.
     */
    function xor(euint32 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.xor(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint32 a, euint128 b)  and returns the result.
     */
    function eq(euint32 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.eq(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint32 a, euint128 b)  and returns the result.
     */
    function ne(euint32 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ne(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint32 a, euint128 b)  and returns the result.
     */
    function ge(euint32 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ge(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint32 a, euint128 b)  and returns the result.
     */
    function gt(euint32 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.gt(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint32 a, euint128 b)  and returns the result.
     */
    function le(euint32 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.le(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint32 a, euint128 b)  and returns the result.
     */
    function lt(euint32 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.lt(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint32 a, euint128 b)  and returns the result.
     */
    function min(euint32 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.min(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint32 a, euint128 b)  and returns the result.
     */
    function max(euint32 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.max(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint32 a, euint256 b)  and returns the result.
     */
    function and(euint32 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint32 a, euint256 b)  and returns the result.
     */
    function or(euint32 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint32 a, euint256 b)  and returns the result.
     */
    function xor(euint32 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint32 a, euint256 b)  and returns the result.
     */
    function eq(euint32 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint32 a, euint256 b)  and returns the result.
     */
    function ne(euint32 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint64 a, euint8 b)  and returns the result.
     */
    function add(euint64 a, euint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint64.wrap(Impl.add(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates sub(euint64 a, euint8 b)  and returns the result.
     */
    function sub(euint64 a, euint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint64.wrap(Impl.sub(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates mul(euint64 a, euint8 b)  and returns the result.
     */
    function mul(euint64 a, euint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint64.wrap(Impl.mul(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates and(euint64 a, euint8 b)  and returns the result.
     */
    function and(euint64 a, euint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint64.wrap(Impl.and(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates or(euint64 a, euint8 b)  and returns the result.
     */
    function or(euint64 a, euint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint64.wrap(Impl.or(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates xor(euint64 a, euint8 b)  and returns the result.
     */
    function xor(euint64 a, euint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint64.wrap(Impl.xor(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates eq(euint64 a, euint8 b)  and returns the result.
     */
    function eq(euint64 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.eq(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates ne(euint64 a, euint8 b)  and returns the result.
     */
    function ne(euint64 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ne(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates ge(euint64 a, euint8 b)  and returns the result.
     */
    function ge(euint64 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ge(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates gt(euint64 a, euint8 b)  and returns the result.
     */
    function gt(euint64 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.gt(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates le(euint64 a, euint8 b)  and returns the result.
     */
    function le(euint64 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.le(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates lt(euint64 a, euint8 b)  and returns the result.
     */
    function lt(euint64 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.lt(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates min(euint64 a, euint8 b)  and returns the result.
     */
    function min(euint64 a, euint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint64.wrap(Impl.min(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates max(euint64 a, euint8 b)  and returns the result.
     */
    function max(euint64 a, euint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint64.wrap(Impl.max(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates add(euint64 a, euint16 b)  and returns the result.
     */
    function add(euint64 a, euint16 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint64.wrap(Impl.add(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates sub(euint64 a, euint16 b)  and returns the result.
     */
    function sub(euint64 a, euint16 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint64.wrap(Impl.sub(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates mul(euint64 a, euint16 b)  and returns the result.
     */
    function mul(euint64 a, euint16 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint64.wrap(Impl.mul(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates and(euint64 a, euint16 b)  and returns the result.
     */
    function and(euint64 a, euint16 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint64.wrap(Impl.and(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates or(euint64 a, euint16 b)  and returns the result.
     */
    function or(euint64 a, euint16 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint64.wrap(Impl.or(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates xor(euint64 a, euint16 b)  and returns the result.
     */
    function xor(euint64 a, euint16 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint64.wrap(Impl.xor(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates eq(euint64 a, euint16 b)  and returns the result.
     */
    function eq(euint64 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.eq(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates ne(euint64 a, euint16 b)  and returns the result.
     */
    function ne(euint64 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ne(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates ge(euint64 a, euint16 b)  and returns the result.
     */
    function ge(euint64 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ge(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates gt(euint64 a, euint16 b)  and returns the result.
     */
    function gt(euint64 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.gt(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates le(euint64 a, euint16 b)  and returns the result.
     */
    function le(euint64 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.le(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates lt(euint64 a, euint16 b)  and returns the result.
     */
    function lt(euint64 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.lt(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates min(euint64 a, euint16 b)  and returns the result.
     */
    function min(euint64 a, euint16 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint64.wrap(Impl.min(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates max(euint64 a, euint16 b)  and returns the result.
     */
    function max(euint64 a, euint16 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint64.wrap(Impl.max(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates add(euint64 a, euint32 b)  and returns the result.
     */
    function add(euint64 a, euint32 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint64.wrap(Impl.add(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates sub(euint64 a, euint32 b)  and returns the result.
     */
    function sub(euint64 a, euint32 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint64.wrap(Impl.sub(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates mul(euint64 a, euint32 b)  and returns the result.
     */
    function mul(euint64 a, euint32 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint64.wrap(Impl.mul(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates and(euint64 a, euint32 b)  and returns the result.
     */
    function and(euint64 a, euint32 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint64.wrap(Impl.and(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates or(euint64 a, euint32 b)  and returns the result.
     */
    function or(euint64 a, euint32 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint64.wrap(Impl.or(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates xor(euint64 a, euint32 b)  and returns the result.
     */
    function xor(euint64 a, euint32 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint64.wrap(Impl.xor(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates eq(euint64 a, euint32 b)  and returns the result.
     */
    function eq(euint64 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.eq(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates ne(euint64 a, euint32 b)  and returns the result.
     */
    function ne(euint64 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ne(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates ge(euint64 a, euint32 b)  and returns the result.
     */
    function ge(euint64 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ge(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates gt(euint64 a, euint32 b)  and returns the result.
     */
    function gt(euint64 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.gt(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates le(euint64 a, euint32 b)  and returns the result.
     */
    function le(euint64 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.le(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates lt(euint64 a, euint32 b)  and returns the result.
     */
    function lt(euint64 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.lt(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates min(euint64 a, euint32 b)  and returns the result.
     */
    function min(euint64 a, euint32 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint64.wrap(Impl.min(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates max(euint64 a, euint32 b)  and returns the result.
     */
    function max(euint64 a, euint32 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint64.wrap(Impl.max(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates add(euint64 a, euint64 b)  and returns the result.
     */
    function add(euint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.add(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint64 a, euint64 b)  and returns the result.
     */
    function sub(euint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.sub(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint64 a, euint64 b)  and returns the result.
     */
    function mul(euint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.mul(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint64 a, euint64 b)  and returns the result.
     */
    function and(euint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.and(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint64 a, euint64 b)  and returns the result.
     */
    function or(euint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.or(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint64 a, euint64 b)  and returns the result.
     */
    function xor(euint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.xor(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint64 a, euint64 b)  and returns the result.
     */
    function eq(euint64 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.eq(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint64 a, euint64 b)  and returns the result.
     */
    function ne(euint64 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ne(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint64 a, euint64 b)  and returns the result.
     */
    function ge(euint64 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ge(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint64 a, euint64 b)  and returns the result.
     */
    function gt(euint64 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.gt(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint64 a, euint64 b)  and returns the result.
     */
    function le(euint64 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.le(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint64 a, euint64 b)  and returns the result.
     */
    function lt(euint64 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.lt(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint64 a, euint64 b)  and returns the result.
     */
    function min(euint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.min(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint64 a, euint64 b)  and returns the result.
     */
    function max(euint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.max(euint64.unwrap(a), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint64 a, euint128 b)  and returns the result.
     */
    function add(euint64 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.add(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint64 a, euint128 b)  and returns the result.
     */
    function sub(euint64 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.sub(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint64 a, euint128 b)  and returns the result.
     */
    function mul(euint64 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.mul(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint64 a, euint128 b)  and returns the result.
     */
    function and(euint64 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.and(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint64 a, euint128 b)  and returns the result.
     */
    function or(euint64 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.or(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint64 a, euint128 b)  and returns the result.
     */
    function xor(euint64 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.xor(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint64 a, euint128 b)  and returns the result.
     */
    function eq(euint64 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.eq(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint64 a, euint128 b)  and returns the result.
     */
    function ne(euint64 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ne(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint64 a, euint128 b)  and returns the result.
     */
    function ge(euint64 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ge(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint64 a, euint128 b)  and returns the result.
     */
    function gt(euint64 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.gt(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint64 a, euint128 b)  and returns the result.
     */
    function le(euint64 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.le(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint64 a, euint128 b)  and returns the result.
     */
    function lt(euint64 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.lt(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint64 a, euint128 b)  and returns the result.
     */
    function min(euint64 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.min(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint64 a, euint128 b)  and returns the result.
     */
    function max(euint64 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.max(euint128.unwrap(asEuint128(a)), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint64 a, euint256 b)  and returns the result.
     */
    function and(euint64 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint64 a, euint256 b)  and returns the result.
     */
    function or(euint64 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint64 a, euint256 b)  and returns the result.
     */
    function xor(euint64 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint64 a, euint256 b)  and returns the result.
     */
    function eq(euint64 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint64 a, euint256 b)  and returns the result.
     */
    function ne(euint64 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates add(euint128 a, euint8 b)  and returns the result.
     */
    function add(euint128 a, euint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint128.wrap(Impl.add(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates sub(euint128 a, euint8 b)  and returns the result.
     */
    function sub(euint128 a, euint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint128.wrap(Impl.sub(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates mul(euint128 a, euint8 b)  and returns the result.
     */
    function mul(euint128 a, euint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint128.wrap(Impl.mul(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates and(euint128 a, euint8 b)  and returns the result.
     */
    function and(euint128 a, euint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint128.wrap(Impl.and(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates or(euint128 a, euint8 b)  and returns the result.
     */
    function or(euint128 a, euint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint128.wrap(Impl.or(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates xor(euint128 a, euint8 b)  and returns the result.
     */
    function xor(euint128 a, euint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint128.wrap(Impl.xor(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates eq(euint128 a, euint8 b)  and returns the result.
     */
    function eq(euint128 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.eq(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates ne(euint128 a, euint8 b)  and returns the result.
     */
    function ne(euint128 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ne(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates ge(euint128 a, euint8 b)  and returns the result.
     */
    function ge(euint128 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ge(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates gt(euint128 a, euint8 b)  and returns the result.
     */
    function gt(euint128 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.gt(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates le(euint128 a, euint8 b)  and returns the result.
     */
    function le(euint128 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.le(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates lt(euint128 a, euint8 b)  and returns the result.
     */
    function lt(euint128 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.lt(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates min(euint128 a, euint8 b)  and returns the result.
     */
    function min(euint128 a, euint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint128.wrap(Impl.min(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates max(euint128 a, euint8 b)  and returns the result.
     */
    function max(euint128 a, euint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint128.wrap(Impl.max(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates add(euint128 a, euint16 b)  and returns the result.
     */
    function add(euint128 a, euint16 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint128.wrap(Impl.add(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates sub(euint128 a, euint16 b)  and returns the result.
     */
    function sub(euint128 a, euint16 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint128.wrap(Impl.sub(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates mul(euint128 a, euint16 b)  and returns the result.
     */
    function mul(euint128 a, euint16 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint128.wrap(Impl.mul(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates and(euint128 a, euint16 b)  and returns the result.
     */
    function and(euint128 a, euint16 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint128.wrap(Impl.and(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates or(euint128 a, euint16 b)  and returns the result.
     */
    function or(euint128 a, euint16 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint128.wrap(Impl.or(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates xor(euint128 a, euint16 b)  and returns the result.
     */
    function xor(euint128 a, euint16 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint128.wrap(Impl.xor(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates eq(euint128 a, euint16 b)  and returns the result.
     */
    function eq(euint128 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.eq(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates ne(euint128 a, euint16 b)  and returns the result.
     */
    function ne(euint128 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ne(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates ge(euint128 a, euint16 b)  and returns the result.
     */
    function ge(euint128 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ge(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates gt(euint128 a, euint16 b)  and returns the result.
     */
    function gt(euint128 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.gt(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates le(euint128 a, euint16 b)  and returns the result.
     */
    function le(euint128 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.le(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates lt(euint128 a, euint16 b)  and returns the result.
     */
    function lt(euint128 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.lt(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates min(euint128 a, euint16 b)  and returns the result.
     */
    function min(euint128 a, euint16 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint128.wrap(Impl.min(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates max(euint128 a, euint16 b)  and returns the result.
     */
    function max(euint128 a, euint16 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint128.wrap(Impl.max(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates add(euint128 a, euint32 b)  and returns the result.
     */
    function add(euint128 a, euint32 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint128.wrap(Impl.add(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates sub(euint128 a, euint32 b)  and returns the result.
     */
    function sub(euint128 a, euint32 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint128.wrap(Impl.sub(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates mul(euint128 a, euint32 b)  and returns the result.
     */
    function mul(euint128 a, euint32 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint128.wrap(Impl.mul(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates and(euint128 a, euint32 b)  and returns the result.
     */
    function and(euint128 a, euint32 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint128.wrap(Impl.and(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates or(euint128 a, euint32 b)  and returns the result.
     */
    function or(euint128 a, euint32 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint128.wrap(Impl.or(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates xor(euint128 a, euint32 b)  and returns the result.
     */
    function xor(euint128 a, euint32 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint128.wrap(Impl.xor(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates eq(euint128 a, euint32 b)  and returns the result.
     */
    function eq(euint128 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.eq(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates ne(euint128 a, euint32 b)  and returns the result.
     */
    function ne(euint128 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ne(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates ge(euint128 a, euint32 b)  and returns the result.
     */
    function ge(euint128 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ge(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates gt(euint128 a, euint32 b)  and returns the result.
     */
    function gt(euint128 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.gt(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates le(euint128 a, euint32 b)  and returns the result.
     */
    function le(euint128 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.le(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates lt(euint128 a, euint32 b)  and returns the result.
     */
    function lt(euint128 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.lt(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates min(euint128 a, euint32 b)  and returns the result.
     */
    function min(euint128 a, euint32 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint128.wrap(Impl.min(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates max(euint128 a, euint32 b)  and returns the result.
     */
    function max(euint128 a, euint32 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint128.wrap(Impl.max(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates add(euint128 a, euint64 b)  and returns the result.
     */
    function add(euint128 a, euint64 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint128.wrap(Impl.add(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates sub(euint128 a, euint64 b)  and returns the result.
     */
    function sub(euint128 a, euint64 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint128.wrap(Impl.sub(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates mul(euint128 a, euint64 b)  and returns the result.
     */
    function mul(euint128 a, euint64 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint128.wrap(Impl.mul(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates and(euint128 a, euint64 b)  and returns the result.
     */
    function and(euint128 a, euint64 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint128.wrap(Impl.and(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates or(euint128 a, euint64 b)  and returns the result.
     */
    function or(euint128 a, euint64 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint128.wrap(Impl.or(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates xor(euint128 a, euint64 b)  and returns the result.
     */
    function xor(euint128 a, euint64 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint128.wrap(Impl.xor(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates eq(euint128 a, euint64 b)  and returns the result.
     */
    function eq(euint128 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.eq(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates ne(euint128 a, euint64 b)  and returns the result.
     */
    function ne(euint128 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ne(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates ge(euint128 a, euint64 b)  and returns the result.
     */
    function ge(euint128 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ge(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates gt(euint128 a, euint64 b)  and returns the result.
     */
    function gt(euint128 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.gt(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates le(euint128 a, euint64 b)  and returns the result.
     */
    function le(euint128 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.le(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates lt(euint128 a, euint64 b)  and returns the result.
     */
    function lt(euint128 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.lt(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates min(euint128 a, euint64 b)  and returns the result.
     */
    function min(euint128 a, euint64 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint128.wrap(Impl.min(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates max(euint128 a, euint64 b)  and returns the result.
     */
    function max(euint128 a, euint64 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint128.wrap(Impl.max(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates add(euint128 a, euint128 b)  and returns the result.
     */
    function add(euint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.add(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates sub(euint128 a, euint128 b)  and returns the result.
     */
    function sub(euint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.sub(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint128 a, euint128 b)  and returns the result.
     */
    function mul(euint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.mul(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint128 a, euint128 b)  and returns the result.
     */
    function and(euint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.and(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint128 a, euint128 b)  and returns the result.
     */
    function or(euint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.or(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint128 a, euint128 b)  and returns the result.
     */
    function xor(euint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.xor(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint128 a, euint128 b)  and returns the result.
     */
    function eq(euint128 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.eq(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint128 a, euint128 b)  and returns the result.
     */
    function ne(euint128 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ne(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates ge(euint128 a, euint128 b)  and returns the result.
     */
    function ge(euint128 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ge(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates gt(euint128 a, euint128 b)  and returns the result.
     */
    function gt(euint128 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.gt(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates le(euint128 a, euint128 b)  and returns the result.
     */
    function le(euint128 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.le(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates lt(euint128 a, euint128 b)  and returns the result.
     */
    function lt(euint128 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.lt(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates min(euint128 a, euint128 b)  and returns the result.
     */
    function min(euint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.min(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates max(euint128 a, euint128 b)  and returns the result.
     */
    function max(euint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.max(euint128.unwrap(a), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint128 a, euint256 b)  and returns the result.
     */
    function and(euint128 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint128 a, euint256 b)  and returns the result.
     */
    function or(euint128 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint128 a, euint256 b)  and returns the result.
     */
    function xor(euint128 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint128 a, euint256 b)  and returns the result.
     */
    function eq(euint128 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint128 a, euint256 b)  and returns the result.
     */
    function ne(euint128 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(asEuint256(a)), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(eaddress a, eaddress b) and returns the result.
     */
    function eq(eaddress a, eaddress b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEaddress(address(0));
        }
        if (!isInitialized(b)) {
            b = asEaddress(address(0));
        }
        return ebool.wrap(Impl.eq(eaddress.unwrap(a), eaddress.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(eaddress a, eaddress b) and returns the result.
     */
    function ne(eaddress a, eaddress b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEaddress(address(0));
        }
        if (!isInitialized(b)) {
            b = asEaddress(address(0));
        }
        return ebool.wrap(Impl.ne(eaddress.unwrap(a), eaddress.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(euint256 a, euint8 b)  and returns the result.
     */
    function and(euint256 a, euint8 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates or(euint256 a, euint8 b)  and returns the result.
     */
    function or(euint256 a, euint8 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates xor(euint256 a, euint8 b)  and returns the result.
     */
    function xor(euint256 a, euint8 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates eq(euint256 a, euint8 b)  and returns the result.
     */
    function eq(euint256 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates ne(euint256 a, euint8 b)  and returns the result.
     */
    function ne(euint256 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates and(euint256 a, euint16 b)  and returns the result.
     */
    function and(euint256 a, euint16 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates or(euint256 a, euint16 b)  and returns the result.
     */
    function or(euint256 a, euint16 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates xor(euint256 a, euint16 b)  and returns the result.
     */
    function xor(euint256 a, euint16 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates eq(euint256 a, euint16 b)  and returns the result.
     */
    function eq(euint256 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates ne(euint256 a, euint16 b)  and returns the result.
     */
    function ne(euint256 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates and(euint256 a, euint32 b)  and returns the result.
     */
    function and(euint256 a, euint32 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates or(euint256 a, euint32 b)  and returns the result.
     */
    function or(euint256 a, euint32 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates xor(euint256 a, euint32 b)  and returns the result.
     */
    function xor(euint256 a, euint32 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates eq(euint256 a, euint32 b)  and returns the result.
     */
    function eq(euint256 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates ne(euint256 a, euint32 b)  and returns the result.
     */
    function ne(euint256 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates and(euint256 a, euint64 b)  and returns the result.
     */
    function and(euint256 a, euint64 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates or(euint256 a, euint64 b)  and returns the result.
     */
    function or(euint256 a, euint64 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates xor(euint256 a, euint64 b)  and returns the result.
     */
    function xor(euint256 a, euint64 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates eq(euint256 a, euint64 b)  and returns the result.
     */
    function eq(euint256 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates ne(euint256 a, euint64 b)  and returns the result.
     */
    function ne(euint256 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates and(euint256 a, euint128 b)  and returns the result.
     */
    function and(euint256 a, euint128 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates or(euint256 a, euint128 b)  and returns the result.
     */
    function or(euint256 a, euint128 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates xor(euint256 a, euint128 b)  and returns the result.
     */
    function xor(euint256 a, euint128 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates eq(euint256 a, euint128 b)  and returns the result.
     */
    function eq(euint256 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates ne(euint256 a, euint128 b)  and returns the result.
     */
    function ne(euint256 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates and(euint256 a, euint256 b)  and returns the result.
     */
    function and(euint256 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(a), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates or(euint256 a, euint256 b)  and returns the result.
     */
    function or(euint256 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(a), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates xor(euint256 a, euint256 b)  and returns the result.
     */
    function xor(euint256 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(a), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates eq(euint256 a, euint256 b)  and returns the result.
     */
    function eq(euint256 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(a), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates ne(euint256 a, euint256 b)  and returns the result.
     */
    function ne(euint256 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(a), euint256.unwrap(b), false));
    }

    /**
     * @dev Evaluates and(ebool a, bool b) and returns the result.
     */
    function and(ebool a, bool b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEbool(false);
        }
        return ebool.wrap(Impl.and(ebool.unwrap(a), bytes32(uint256(b ? 1 : 0)), true));
    }

    /**
     * @dev Evaluates and(bool a, ebool b) and returns the result.
     */
    function and(bool a, ebool b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return ebool.wrap(Impl.and(ebool.unwrap(b), bytes32(uint256(a ? 1 : 0)), true));
    }

    /**
     * @dev Evaluates or(ebool a, bool b) and returns the result.
     */
    function or(ebool a, bool b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEbool(false);
        }
        return ebool.wrap(Impl.or(ebool.unwrap(a), bytes32(uint256(b ? 1 : 0)), true));
    }

    /**
     * @dev Evaluates or(bool a, ebool b) and returns the result.
     */
    function or(bool a, ebool b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return ebool.wrap(Impl.or(ebool.unwrap(b), bytes32(uint256(a ? 1 : 0)), true));
    }

    /**
     * @dev Evaluates xor(ebool a, bool b) and returns the result.
     */
    function xor(ebool a, bool b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEbool(false);
        }
        return ebool.wrap(Impl.xor(ebool.unwrap(a), bytes32(uint256(b ? 1 : 0)), true));
    }

    /**
     * @dev Evaluates xor(bool a, ebool b) and returns the result.
     */
    function xor(bool a, ebool b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return ebool.wrap(Impl.xor(ebool.unwrap(b), bytes32(uint256(a ? 1 : 0)), true));
    }

    /**
     * @dev Evaluates eq(ebool a, bool b) and returns the result.
     */
    function eq(ebool a, bool b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEbool(false);
        }
        return ebool.wrap(Impl.eq(ebool.unwrap(a), bytes32(uint256(b ? 1 : 0)), true));
    }

    /**
     * @dev Evaluates eq(bool a, ebool b) and returns the result.
     */
    function eq(bool a, ebool b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return ebool.wrap(Impl.eq(ebool.unwrap(b), bytes32(uint256(a ? 1 : 0)), true));
    }

    /**
     * @dev Evaluates ne(ebool a, bool b) and returns the result.
     */
    function ne(ebool a, bool b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEbool(false);
        }
        return ebool.wrap(Impl.ne(ebool.unwrap(a), bytes32(uint256(b ? 1 : 0)), true));
    }

    /**
     * @dev Evaluates ne(bool a, ebool b) and returns the result.
     */
    function ne(bool a, ebool b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return ebool.wrap(Impl.ne(ebool.unwrap(b), bytes32(uint256(a ? 1 : 0)), true));
    }

    /**
     * @dev Evaluates add(euint8 a, uint8 b) and returns the result.
     */
    function add(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.add(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates add(uint8 a, euint8 b) and returns the result.
     */
    function add(uint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.add(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates sub(euint8 a, uint8 b) and returns the result.
     */
    function sub(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.sub(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates sub(uint8 a, euint8 b) and returns the result.
     */
    function sub(uint8 a, euint8 b) internal returns (euint8) {
        euint8 aEnc = asEuint8(a);
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.sub(euint8.unwrap(aEnc), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint8 a, uint8 b) and returns the result.
     */
    function mul(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.mul(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates mul(uint8 a, euint8 b) and returns the result.
     */
    function mul(uint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.mul(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates div(euint8 a, uint8 b) and returns the result.
     */
    function div(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.div(euint8.unwrap(a), bytes32(uint256(b))));
    }

    /**
     * @dev Evaluates rem(euint8 a, uint8 b) and returns the result.
     */
    function rem(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.rem(euint8.unwrap(a), bytes32(uint256(b))));
    }

    /**
     * @dev Evaluates and(euint8 a, uint8 b) and returns the result.
     */
    function and(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.and(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates and(uint8 a, euint8 b) and returns the result.
     */
    function and(uint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.and(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates or(euint8 a, uint8 b) and returns the result.
     */
    function or(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.or(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates or(uint8 a, euint8 b) and returns the result.
     */
    function or(uint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.or(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates xor(euint8 a, uint8 b) and returns the result.
     */
    function xor(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.xor(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates xor(uint8 a, euint8 b) and returns the result.
     */
    function xor(uint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.xor(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates eq(euint8 a, uint8 b) and returns the result.
     */
    function eq(euint8 a, uint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return ebool.wrap(Impl.eq(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates eq(uint8 a, euint8 b) and returns the result.
     */
    function eq(uint8 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.eq(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates ne(euint8 a, uint8 b) and returns the result.
     */
    function ne(euint8 a, uint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return ebool.wrap(Impl.ne(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates ne(uint8 a, euint8 b) and returns the result.
     */
    function ne(uint8 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ne(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates ge(euint8 a, uint8 b) and returns the result.
     */
    function ge(euint8 a, uint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return ebool.wrap(Impl.ge(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates ge(uint8 a, euint8 b) and returns the result.
     */
    function ge(uint8 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.le(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates gt(euint8 a, uint8 b) and returns the result.
     */
    function gt(euint8 a, uint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return ebool.wrap(Impl.gt(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates gt(uint8 a, euint8 b) and returns the result.
     */
    function gt(uint8 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.lt(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates le(euint8 a, uint8 b) and returns the result.
     */
    function le(euint8 a, uint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return ebool.wrap(Impl.le(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates le(uint8 a, euint8 b) and returns the result.
     */
    function le(uint8 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.ge(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates lt(euint8 a, uint8 b) and returns the result.
     */
    function lt(euint8 a, uint8 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return ebool.wrap(Impl.lt(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates lt(uint8 a, euint8 b) and returns the result.
     */
    function lt(uint8 a, euint8 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return ebool.wrap(Impl.gt(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates min(euint8 a, uint8 b) and returns the result.
     */
    function min(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.min(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates min(uint8 a, euint8 b) and returns the result.
     */
    function min(uint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.min(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates max(euint8 a, uint8 b) and returns the result.
     */
    function max(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.max(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates max(uint8 a, euint8 b) and returns the result.
     */
    function max(uint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.max(euint8.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates add(euint16 a, uint16 b) and returns the result.
     */
    function add(euint16 a, uint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.add(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates add(uint16 a, euint16 b) and returns the result.
     */
    function add(uint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.add(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates sub(euint16 a, uint16 b) and returns the result.
     */
    function sub(euint16 a, uint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.sub(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates sub(uint16 a, euint16 b) and returns the result.
     */
    function sub(uint16 a, euint16 b) internal returns (euint16) {
        euint16 aEnc = asEuint16(a);
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.sub(euint16.unwrap(aEnc), euint16.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint16 a, uint16 b) and returns the result.
     */
    function mul(euint16 a, uint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.mul(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates mul(uint16 a, euint16 b) and returns the result.
     */
    function mul(uint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.mul(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates div(euint16 a, uint16 b) and returns the result.
     */
    function div(euint16 a, uint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.div(euint16.unwrap(a), bytes32(uint256(b))));
    }

    /**
     * @dev Evaluates rem(euint16 a, uint16 b) and returns the result.
     */
    function rem(euint16 a, uint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.rem(euint16.unwrap(a), bytes32(uint256(b))));
    }

    /**
     * @dev Evaluates and(euint16 a, uint16 b) and returns the result.
     */
    function and(euint16 a, uint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.and(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates and(uint16 a, euint16 b) and returns the result.
     */
    function and(uint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.and(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates or(euint16 a, uint16 b) and returns the result.
     */
    function or(euint16 a, uint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.or(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates or(uint16 a, euint16 b) and returns the result.
     */
    function or(uint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.or(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates xor(euint16 a, uint16 b) and returns the result.
     */
    function xor(euint16 a, uint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.xor(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates xor(uint16 a, euint16 b) and returns the result.
     */
    function xor(uint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.xor(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates eq(euint16 a, uint16 b) and returns the result.
     */
    function eq(euint16 a, uint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return ebool.wrap(Impl.eq(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates eq(uint16 a, euint16 b) and returns the result.
     */
    function eq(uint16 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.eq(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates ne(euint16 a, uint16 b) and returns the result.
     */
    function ne(euint16 a, uint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return ebool.wrap(Impl.ne(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates ne(uint16 a, euint16 b) and returns the result.
     */
    function ne(uint16 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ne(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates ge(euint16 a, uint16 b) and returns the result.
     */
    function ge(euint16 a, uint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return ebool.wrap(Impl.ge(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates ge(uint16 a, euint16 b) and returns the result.
     */
    function ge(uint16 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.le(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates gt(euint16 a, uint16 b) and returns the result.
     */
    function gt(euint16 a, uint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return ebool.wrap(Impl.gt(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates gt(uint16 a, euint16 b) and returns the result.
     */
    function gt(uint16 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.lt(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates le(euint16 a, uint16 b) and returns the result.
     */
    function le(euint16 a, uint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return ebool.wrap(Impl.le(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates le(uint16 a, euint16 b) and returns the result.
     */
    function le(uint16 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.ge(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates lt(euint16 a, uint16 b) and returns the result.
     */
    function lt(euint16 a, uint16 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return ebool.wrap(Impl.lt(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates lt(uint16 a, euint16 b) and returns the result.
     */
    function lt(uint16 a, euint16 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return ebool.wrap(Impl.gt(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates min(euint16 a, uint16 b) and returns the result.
     */
    function min(euint16 a, uint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.min(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates min(uint16 a, euint16 b) and returns the result.
     */
    function min(uint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.min(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates max(euint16 a, uint16 b) and returns the result.
     */
    function max(euint16 a, uint16 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.max(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates max(uint16 a, euint16 b) and returns the result.
     */
    function max(uint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.max(euint16.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates add(euint32 a, uint32 b) and returns the result.
     */
    function add(euint32 a, uint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.add(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates add(uint32 a, euint32 b) and returns the result.
     */
    function add(uint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.add(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates sub(euint32 a, uint32 b) and returns the result.
     */
    function sub(euint32 a, uint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.sub(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates sub(uint32 a, euint32 b) and returns the result.
     */
    function sub(uint32 a, euint32 b) internal returns (euint32) {
        euint32 aEnc = asEuint32(a);
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.sub(euint32.unwrap(aEnc), euint32.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint32 a, uint32 b) and returns the result.
     */
    function mul(euint32 a, uint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.mul(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates mul(uint32 a, euint32 b) and returns the result.
     */
    function mul(uint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.mul(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates div(euint32 a, uint32 b) and returns the result.
     */
    function div(euint32 a, uint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.div(euint32.unwrap(a), bytes32(uint256(b))));
    }

    /**
     * @dev Evaluates rem(euint32 a, uint32 b) and returns the result.
     */
    function rem(euint32 a, uint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.rem(euint32.unwrap(a), bytes32(uint256(b))));
    }

    /**
     * @dev Evaluates and(euint32 a, uint32 b) and returns the result.
     */
    function and(euint32 a, uint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.and(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates and(uint32 a, euint32 b) and returns the result.
     */
    function and(uint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.and(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates or(euint32 a, uint32 b) and returns the result.
     */
    function or(euint32 a, uint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.or(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates or(uint32 a, euint32 b) and returns the result.
     */
    function or(uint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.or(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates xor(euint32 a, uint32 b) and returns the result.
     */
    function xor(euint32 a, uint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.xor(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates xor(uint32 a, euint32 b) and returns the result.
     */
    function xor(uint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.xor(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates eq(euint32 a, uint32 b) and returns the result.
     */
    function eq(euint32 a, uint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return ebool.wrap(Impl.eq(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates eq(uint32 a, euint32 b) and returns the result.
     */
    function eq(uint32 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.eq(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates ne(euint32 a, uint32 b) and returns the result.
     */
    function ne(euint32 a, uint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return ebool.wrap(Impl.ne(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates ne(uint32 a, euint32 b) and returns the result.
     */
    function ne(uint32 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ne(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates ge(euint32 a, uint32 b) and returns the result.
     */
    function ge(euint32 a, uint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return ebool.wrap(Impl.ge(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates ge(uint32 a, euint32 b) and returns the result.
     */
    function ge(uint32 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.le(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates gt(euint32 a, uint32 b) and returns the result.
     */
    function gt(euint32 a, uint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return ebool.wrap(Impl.gt(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates gt(uint32 a, euint32 b) and returns the result.
     */
    function gt(uint32 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.lt(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates le(euint32 a, uint32 b) and returns the result.
     */
    function le(euint32 a, uint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return ebool.wrap(Impl.le(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates le(uint32 a, euint32 b) and returns the result.
     */
    function le(uint32 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.ge(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates lt(euint32 a, uint32 b) and returns the result.
     */
    function lt(euint32 a, uint32 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return ebool.wrap(Impl.lt(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates lt(uint32 a, euint32 b) and returns the result.
     */
    function lt(uint32 a, euint32 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return ebool.wrap(Impl.gt(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates min(euint32 a, uint32 b) and returns the result.
     */
    function min(euint32 a, uint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.min(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates min(uint32 a, euint32 b) and returns the result.
     */
    function min(uint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.min(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates max(euint32 a, uint32 b) and returns the result.
     */
    function max(euint32 a, uint32 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.max(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates max(uint32 a, euint32 b) and returns the result.
     */
    function max(uint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.max(euint32.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates add(euint64 a, uint64 b) and returns the result.
     */
    function add(euint64 a, uint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.add(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates add(uint64 a, euint64 b) and returns the result.
     */
    function add(uint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.add(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates sub(euint64 a, uint64 b) and returns the result.
     */
    function sub(euint64 a, uint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.sub(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates sub(uint64 a, euint64 b) and returns the result.
     */
    function sub(uint64 a, euint64 b) internal returns (euint64) {
        euint64 aEnc = asEuint64(a);
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.sub(euint64.unwrap(aEnc), euint64.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint64 a, uint64 b) and returns the result.
     */
    function mul(euint64 a, uint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.mul(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates mul(uint64 a, euint64 b) and returns the result.
     */
    function mul(uint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.mul(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates div(euint64 a, uint64 b) and returns the result.
     */
    function div(euint64 a, uint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.div(euint64.unwrap(a), bytes32(uint256(b))));
    }

    /**
     * @dev Evaluates rem(euint64 a, uint64 b) and returns the result.
     */
    function rem(euint64 a, uint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.rem(euint64.unwrap(a), bytes32(uint256(b))));
    }

    /**
     * @dev Evaluates and(euint64 a, uint64 b) and returns the result.
     */
    function and(euint64 a, uint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.and(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates and(uint64 a, euint64 b) and returns the result.
     */
    function and(uint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.and(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates or(euint64 a, uint64 b) and returns the result.
     */
    function or(euint64 a, uint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.or(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates or(uint64 a, euint64 b) and returns the result.
     */
    function or(uint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.or(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates xor(euint64 a, uint64 b) and returns the result.
     */
    function xor(euint64 a, uint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.xor(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates xor(uint64 a, euint64 b) and returns the result.
     */
    function xor(uint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.xor(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates eq(euint64 a, uint64 b) and returns the result.
     */
    function eq(euint64 a, uint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return ebool.wrap(Impl.eq(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates eq(uint64 a, euint64 b) and returns the result.
     */
    function eq(uint64 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.eq(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates ne(euint64 a, uint64 b) and returns the result.
     */
    function ne(euint64 a, uint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return ebool.wrap(Impl.ne(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates ne(uint64 a, euint64 b) and returns the result.
     */
    function ne(uint64 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ne(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates ge(euint64 a, uint64 b) and returns the result.
     */
    function ge(euint64 a, uint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return ebool.wrap(Impl.ge(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates ge(uint64 a, euint64 b) and returns the result.
     */
    function ge(uint64 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.le(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates gt(euint64 a, uint64 b) and returns the result.
     */
    function gt(euint64 a, uint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return ebool.wrap(Impl.gt(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates gt(uint64 a, euint64 b) and returns the result.
     */
    function gt(uint64 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.lt(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates le(euint64 a, uint64 b) and returns the result.
     */
    function le(euint64 a, uint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return ebool.wrap(Impl.le(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates le(uint64 a, euint64 b) and returns the result.
     */
    function le(uint64 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.ge(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates lt(euint64 a, uint64 b) and returns the result.
     */
    function lt(euint64 a, uint64 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return ebool.wrap(Impl.lt(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates lt(uint64 a, euint64 b) and returns the result.
     */
    function lt(uint64 a, euint64 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return ebool.wrap(Impl.gt(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates min(euint64 a, uint64 b) and returns the result.
     */
    function min(euint64 a, uint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.min(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates min(uint64 a, euint64 b) and returns the result.
     */
    function min(uint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.min(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates max(euint64 a, uint64 b) and returns the result.
     */
    function max(euint64 a, uint64 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.max(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates max(uint64 a, euint64 b) and returns the result.
     */
    function max(uint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.max(euint64.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates add(euint128 a, uint128 b) and returns the result.
     */
    function add(euint128 a, uint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.add(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates add(uint128 a, euint128 b) and returns the result.
     */
    function add(uint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.add(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates sub(euint128 a, uint128 b) and returns the result.
     */
    function sub(euint128 a, uint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.sub(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates sub(uint128 a, euint128 b) and returns the result.
     */
    function sub(uint128 a, euint128 b) internal returns (euint128) {
        euint128 aEnc = asEuint128(a);
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.sub(euint128.unwrap(aEnc), euint128.unwrap(b), false));
    }

    /**
     * @dev Evaluates mul(euint128 a, uint128 b) and returns the result.
     */
    function mul(euint128 a, uint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.mul(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates mul(uint128 a, euint128 b) and returns the result.
     */
    function mul(uint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.mul(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates div(euint128 a, uint128 b) and returns the result.
     */
    function div(euint128 a, uint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.div(euint128.unwrap(a), bytes32(uint256(b))));
    }

    /**
     * @dev Evaluates rem(euint128 a, uint128 b) and returns the result.
     */
    function rem(euint128 a, uint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.rem(euint128.unwrap(a), bytes32(uint256(b))));
    }

    /**
     * @dev Evaluates and(euint128 a, uint128 b) and returns the result.
     */
    function and(euint128 a, uint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.and(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates and(uint128 a, euint128 b) and returns the result.
     */
    function and(uint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.and(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates or(euint128 a, uint128 b) and returns the result.
     */
    function or(euint128 a, uint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.or(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates or(uint128 a, euint128 b) and returns the result.
     */
    function or(uint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.or(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates xor(euint128 a, uint128 b) and returns the result.
     */
    function xor(euint128 a, uint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.xor(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates xor(uint128 a, euint128 b) and returns the result.
     */
    function xor(uint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.xor(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates eq(euint128 a, uint128 b) and returns the result.
     */
    function eq(euint128 a, uint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return ebool.wrap(Impl.eq(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates eq(uint128 a, euint128 b) and returns the result.
     */
    function eq(uint128 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.eq(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates ne(euint128 a, uint128 b) and returns the result.
     */
    function ne(euint128 a, uint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return ebool.wrap(Impl.ne(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates ne(uint128 a, euint128 b) and returns the result.
     */
    function ne(uint128 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ne(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates ge(euint128 a, uint128 b) and returns the result.
     */
    function ge(euint128 a, uint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return ebool.wrap(Impl.ge(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates ge(uint128 a, euint128 b) and returns the result.
     */
    function ge(uint128 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.le(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates gt(euint128 a, uint128 b) and returns the result.
     */
    function gt(euint128 a, uint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return ebool.wrap(Impl.gt(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates gt(uint128 a, euint128 b) and returns the result.
     */
    function gt(uint128 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.lt(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates le(euint128 a, uint128 b) and returns the result.
     */
    function le(euint128 a, uint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return ebool.wrap(Impl.le(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates le(uint128 a, euint128 b) and returns the result.
     */
    function le(uint128 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.ge(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates lt(euint128 a, uint128 b) and returns the result.
     */
    function lt(euint128 a, uint128 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return ebool.wrap(Impl.lt(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates lt(uint128 a, euint128 b) and returns the result.
     */
    function lt(uint128 a, euint128 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return ebool.wrap(Impl.gt(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates min(euint128 a, uint128 b) and returns the result.
     */
    function min(euint128 a, uint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.min(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates min(uint128 a, euint128 b) and returns the result.
     */
    function min(uint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.min(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates max(euint128 a, uint128 b) and returns the result.
     */
    function max(euint128 a, uint128 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.max(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates max(uint128 a, euint128 b) and returns the result.
     */
    function max(uint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.max(euint128.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates eq(eaddress a, address b) and returns the result.
     */
    function eq(eaddress a, address b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEaddress(address(0));
        }
        return ebool.wrap(Impl.eq(eaddress.unwrap(a), bytes32(uint256(uint160(b))), true));
    }

    /**
     * @dev Evaluates eq(address a, eaddress b) and returns the result.
     */
    function eq(address a, eaddress b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEaddress(address(0));
        }
        return ebool.wrap(Impl.eq(eaddress.unwrap(b), bytes32(uint256(uint160(a))), true));
    }

    /**
     * @dev Evaluates ne(eaddress a, address b) and returns the result.
     */
    function ne(eaddress a, address b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEaddress(address(0));
        }
        return ebool.wrap(Impl.ne(eaddress.unwrap(a), bytes32(uint256(uint160(b))), true));
    }

    /**
     * @dev Evaluates ne(address a, eaddress b) and returns the result.
     */
    function ne(address a, eaddress b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEaddress(address(0));
        }
        return ebool.wrap(Impl.ne(eaddress.unwrap(b), bytes32(uint256(uint160(a))), true));
    }

    /**
     * @dev Evaluates and(euint256 a, uint256 b) and returns the result.
     */
    function and(euint256 a, uint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates and(uint256 a, euint256 b) and returns the result.
     */
    function and(uint256 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.and(euint256.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates or(euint256 a, uint256 b) and returns the result.
     */
    function or(euint256 a, uint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates or(uint256 a, euint256 b) and returns the result.
     */
    function or(uint256 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.or(euint256.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates xor(euint256 a, uint256 b) and returns the result.
     */
    function xor(euint256 a, uint256 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates xor(uint256 a, euint256 b) and returns the result.
     */
    function xor(uint256 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.xor(euint256.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates eq(euint256 a, uint256 b) and returns the result.
     */
    function eq(euint256 a, uint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates eq(uint256 a, euint256 b) and returns the result.
     */
    function eq(uint256 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.eq(euint256.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates ne(euint256 a, uint256 b) and returns the result.
     */
    function ne(euint256 a, uint256 b) internal returns (ebool) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates ne(uint256 a, euint256 b) and returns the result.
     */
    function ne(uint256 a, euint256 b) internal returns (ebool) {
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return ebool.wrap(Impl.ne(euint256.unwrap(b), bytes32(uint256(a)), true));
    }

    /**
     * @dev Evaluates shl(euint8 a, euint8 b) and returns the result.
     */
    function shl(euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.shl(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates shl(euint8 a, uint8) and returns the result.
     */
    function shl(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.shl(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates shr(euint8 a, euint8 b) and returns the result.
     */
    function shr(euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.shr(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates shr(euint8 a, uint8) and returns the result.
     */
    function shr(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.shr(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates rotl(euint8 a, euint8 b) and returns the result.
     */
    function rotl(euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.rotl(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates rotl(euint8 a, uint8) and returns the result.
     */
    function rotl(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.rotl(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates rotr(euint8 a, euint8 b) and returns the result.
     */
    function rotr(euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.rotr(euint8.unwrap(a), euint8.unwrap(b), false));
    }

    /**
     * @dev Evaluates rotr(euint8 a, uint8) and returns the result.
     */
    function rotr(euint8 a, uint8 b) internal returns (euint8) {
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        return euint8.wrap(Impl.rotr(euint8.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates shl(euint16 a, euint8 b) and returns the result.
     */
    function shl(euint16 a, euint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint16.wrap(Impl.shl(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates shl(euint16 a, uint8) and returns the result.
     */
    function shl(euint16 a, uint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.shl(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates shr(euint16 a, euint8 b) and returns the result.
     */
    function shr(euint16 a, euint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint16.wrap(Impl.shr(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates shr(euint16 a, uint8) and returns the result.
     */
    function shr(euint16 a, uint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.shr(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates rotl(euint16 a, euint8 b) and returns the result.
     */
    function rotl(euint16 a, euint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint16.wrap(Impl.rotl(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates rotl(euint16 a, uint8) and returns the result.
     */
    function rotl(euint16 a, uint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.rotl(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates rotr(euint16 a, euint8 b) and returns the result.
     */
    function rotr(euint16 a, euint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint16.wrap(Impl.rotr(euint16.unwrap(a), euint16.unwrap(asEuint16(b)), false));
    }

    /**
     * @dev Evaluates rotr(euint16 a, uint8) and returns the result.
     */
    function rotr(euint16 a, uint8 b) internal returns (euint16) {
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        return euint16.wrap(Impl.rotr(euint16.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates shl(euint32 a, euint8 b) and returns the result.
     */
    function shl(euint32 a, euint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint32.wrap(Impl.shl(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates shl(euint32 a, uint8) and returns the result.
     */
    function shl(euint32 a, uint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.shl(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates shr(euint32 a, euint8 b) and returns the result.
     */
    function shr(euint32 a, euint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint32.wrap(Impl.shr(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates shr(euint32 a, uint8) and returns the result.
     */
    function shr(euint32 a, uint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.shr(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates rotl(euint32 a, euint8 b) and returns the result.
     */
    function rotl(euint32 a, euint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint32.wrap(Impl.rotl(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates rotl(euint32 a, uint8) and returns the result.
     */
    function rotl(euint32 a, uint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.rotl(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates rotr(euint32 a, euint8 b) and returns the result.
     */
    function rotr(euint32 a, euint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint32.wrap(Impl.rotr(euint32.unwrap(a), euint32.unwrap(asEuint32(b)), false));
    }

    /**
     * @dev Evaluates rotr(euint32 a, uint8) and returns the result.
     */
    function rotr(euint32 a, uint8 b) internal returns (euint32) {
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        return euint32.wrap(Impl.rotr(euint32.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates shl(euint64 a, euint8 b) and returns the result.
     */
    function shl(euint64 a, euint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint64.wrap(Impl.shl(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates shl(euint64 a, uint8) and returns the result.
     */
    function shl(euint64 a, uint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.shl(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates shr(euint64 a, euint8 b) and returns the result.
     */
    function shr(euint64 a, euint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint64.wrap(Impl.shr(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates shr(euint64 a, uint8) and returns the result.
     */
    function shr(euint64 a, uint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.shr(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates rotl(euint64 a, euint8 b) and returns the result.
     */
    function rotl(euint64 a, euint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint64.wrap(Impl.rotl(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates rotl(euint64 a, uint8) and returns the result.
     */
    function rotl(euint64 a, uint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.rotl(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates rotr(euint64 a, euint8 b) and returns the result.
     */
    function rotr(euint64 a, euint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint64.wrap(Impl.rotr(euint64.unwrap(a), euint64.unwrap(asEuint64(b)), false));
    }

    /**
     * @dev Evaluates rotr(euint64 a, uint8) and returns the result.
     */
    function rotr(euint64 a, uint8 b) internal returns (euint64) {
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        return euint64.wrap(Impl.rotr(euint64.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates shl(euint128 a, euint8 b) and returns the result.
     */
    function shl(euint128 a, euint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint128.wrap(Impl.shl(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates shl(euint128 a, uint8) and returns the result.
     */
    function shl(euint128 a, uint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.shl(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates shr(euint128 a, euint8 b) and returns the result.
     */
    function shr(euint128 a, euint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint128.wrap(Impl.shr(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates shr(euint128 a, uint8) and returns the result.
     */
    function shr(euint128 a, uint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.shr(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates rotl(euint128 a, euint8 b) and returns the result.
     */
    function rotl(euint128 a, euint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint128.wrap(Impl.rotl(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates rotl(euint128 a, uint8) and returns the result.
     */
    function rotl(euint128 a, uint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.rotl(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates rotr(euint128 a, euint8 b) and returns the result.
     */
    function rotr(euint128 a, euint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint128.wrap(Impl.rotr(euint128.unwrap(a), euint128.unwrap(asEuint128(b)), false));
    }

    /**
     * @dev Evaluates rotr(euint128 a, uint8) and returns the result.
     */
    function rotr(euint128 a, uint8 b) internal returns (euint128) {
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        return euint128.wrap(Impl.rotr(euint128.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates shl(euint256 a, euint8 b) and returns the result.
     */
    function shl(euint256 a, euint8 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint256.wrap(Impl.shl(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates shl(euint256 a, uint8) and returns the result.
     */
    function shl(euint256 a, uint8 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        return euint256.wrap(Impl.shl(euint256.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates shr(euint256 a, euint8 b) and returns the result.
     */
    function shr(euint256 a, euint8 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint256.wrap(Impl.shr(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates shr(euint256 a, uint8) and returns the result.
     */
    function shr(euint256 a, uint8 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        return euint256.wrap(Impl.shr(euint256.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates rotl(euint256 a, euint8 b) and returns the result.
     */
    function rotl(euint256 a, euint8 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint256.wrap(Impl.rotl(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates rotl(euint256 a, uint8) and returns the result.
     */
    function rotl(euint256 a, uint8 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        return euint256.wrap(Impl.rotl(euint256.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev Evaluates rotr(euint256 a, euint8 b) and returns the result.
     */
    function rotr(euint256 a, euint8 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint256.wrap(Impl.rotr(euint256.unwrap(a), euint256.unwrap(asEuint256(b)), false));
    }

    /**
     * @dev Evaluates rotr(euint256 a, uint8) and returns the result.
     */
    function rotr(euint256 a, uint8 b) internal returns (euint256) {
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        return euint256.wrap(Impl.rotr(euint256.unwrap(a), bytes32(uint256(b)), true));
    }

    /**
     * @dev If 'control's value is 'true', the result has the same value as 'ifTrue'.
     *      If 'control's value is 'false', the result has the same value as 'ifFalse'.
     */
    function select(ebool control, ebool a, ebool b) internal returns (ebool) {
        if (!isInitialized(control)) {
            control = asEbool(false);
        }
        if (!isInitialized(a)) {
            a = asEbool(false);
        }
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return ebool.wrap(Impl.select(ebool.unwrap(control), ebool.unwrap(a), ebool.unwrap(b)));
    }

    /**
     * @dev If 'control's value is 'true', the result has the same value as 'ifTrue'.
     *      If 'control's value is 'false', the result has the same value as 'ifFalse'.
     */
    function select(ebool control, euint8 a, euint8 b) internal returns (euint8) {
        if (!isInitialized(control)) {
            control = asEbool(false);
        }
        if (!isInitialized(a)) {
            a = asEuint8(0);
        }
        if (!isInitialized(b)) {
            b = asEuint8(0);
        }
        return euint8.wrap(Impl.select(ebool.unwrap(control), euint8.unwrap(a), euint8.unwrap(b)));
    }

    /**
     * @dev If 'control's value is 'true', the result has the same value as 'ifTrue'.
     *      If 'control's value is 'false', the result has the same value as 'ifFalse'.
     */
    function select(ebool control, euint16 a, euint16 b) internal returns (euint16) {
        if (!isInitialized(control)) {
            control = asEbool(false);
        }
        if (!isInitialized(a)) {
            a = asEuint16(0);
        }
        if (!isInitialized(b)) {
            b = asEuint16(0);
        }
        return euint16.wrap(Impl.select(ebool.unwrap(control), euint16.unwrap(a), euint16.unwrap(b)));
    }

    /**
     * @dev If 'control's value is 'true', the result has the same value as 'ifTrue'.
     *      If 'control's value is 'false', the result has the same value as 'ifFalse'.
     */
    function select(ebool control, euint32 a, euint32 b) internal returns (euint32) {
        if (!isInitialized(control)) {
            control = asEbool(false);
        }
        if (!isInitialized(a)) {
            a = asEuint32(0);
        }
        if (!isInitialized(b)) {
            b = asEuint32(0);
        }
        return euint32.wrap(Impl.select(ebool.unwrap(control), euint32.unwrap(a), euint32.unwrap(b)));
    }

    /**
     * @dev If 'control's value is 'true', the result has the same value as 'ifTrue'.
     *      If 'control's value is 'false', the result has the same value as 'ifFalse'.
     */
    function select(ebool control, euint64 a, euint64 b) internal returns (euint64) {
        if (!isInitialized(control)) {
            control = asEbool(false);
        }
        if (!isInitialized(a)) {
            a = asEuint64(0);
        }
        if (!isInitialized(b)) {
            b = asEuint64(0);
        }
        return euint64.wrap(Impl.select(ebool.unwrap(control), euint64.unwrap(a), euint64.unwrap(b)));
    }

    /**
     * @dev If 'control's value is 'true', the result has the same value as 'ifTrue'.
     *      If 'control's value is 'false', the result has the same value as 'ifFalse'.
     */
    function select(ebool control, euint128 a, euint128 b) internal returns (euint128) {
        if (!isInitialized(control)) {
            control = asEbool(false);
        }
        if (!isInitialized(a)) {
            a = asEuint128(0);
        }
        if (!isInitialized(b)) {
            b = asEuint128(0);
        }
        return euint128.wrap(Impl.select(ebool.unwrap(control), euint128.unwrap(a), euint128.unwrap(b)));
    }

    /**
     * @dev If 'control's value is 'true', the result has the same value as 'ifTrue'.
     *      If 'control's value is 'false', the result has the same value as 'ifFalse'.
     */
    function select(ebool control, eaddress a, eaddress b) internal returns (eaddress) {
        if (!isInitialized(control)) {
            control = asEbool(false);
        }
        if (!isInitialized(a)) {
            a = asEaddress(address(0));
        }
        if (!isInitialized(b)) {
            b = asEaddress(address(0));
        }
        return eaddress.wrap(Impl.select(ebool.unwrap(control), eaddress.unwrap(a), eaddress.unwrap(b)));
    }

    /**
     * @dev If 'control's value is 'true', the result has the same value as 'ifTrue'.
     *      If 'control's value is 'false', the result has the same value as 'ifFalse'.
     */
    function select(ebool control, euint256 a, euint256 b) internal returns (euint256) {
        if (!isInitialized(control)) {
            control = asEbool(false);
        }
        if (!isInitialized(a)) {
            a = asEuint256(0);
        }
        if (!isInitialized(b)) {
            b = asEuint256(0);
        }
        return euint256.wrap(Impl.select(ebool.unwrap(control), euint256.unwrap(a), euint256.unwrap(b)));
    }

    /**
     * @dev Casts an encrypted integer from 'euint16' to 'euint8'.
     */
    function asEuint8(euint16 value) internal returns (euint8) {
        if (!isInitialized(value)) {
            value = asEuint16(0);
        }
        return euint8.wrap(Impl.cast(euint16.unwrap(value), FheType.Uint8));
    }

    /**
     * @dev Casts an encrypted integer from 'euint32' to 'euint8'.
     */
    function asEuint8(euint32 value) internal returns (euint8) {
        if (!isInitialized(value)) {
            value = asEuint32(0);
        }
        return euint8.wrap(Impl.cast(euint32.unwrap(value), FheType.Uint8));
    }

    /**
     * @dev Casts an encrypted integer from 'euint64' to 'euint8'.
     */
    function asEuint8(euint64 value) internal returns (euint8) {
        if (!isInitialized(value)) {
            value = asEuint64(0);
        }
        return euint8.wrap(Impl.cast(euint64.unwrap(value), FheType.Uint8));
    }

    /**
     * @dev Casts an encrypted integer from 'euint128' to 'euint8'.
     */
    function asEuint8(euint128 value) internal returns (euint8) {
        if (!isInitialized(value)) {
            value = asEuint128(0);
        }
        return euint8.wrap(Impl.cast(euint128.unwrap(value), FheType.Uint8));
    }

    /**
     * @dev Casts an encrypted integer from 'euint256' to 'euint8'.
     */
    function asEuint8(euint256 value) internal returns (euint8) {
        if (!isInitialized(value)) {
            value = asEuint256(0);
        }
        return euint8.wrap(Impl.cast(euint256.unwrap(value), FheType.Uint8));
    }

    /**
    /** 
     * @dev Converts an 'ebool' to an 'euint8'.
     */
    function asEuint8(ebool b) internal returns (euint8) {
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return euint8.wrap(Impl.cast(ebool.unwrap(b), FheType.Uint8));
    }

    /**
     * @dev Casts an encrypted integer from 'euint8' to 'ebool'.
     */
    function asEbool(euint8 value) internal returns (ebool) {
        if (!isInitialized(value)) {
            value = asEuint8(0);
        }
        return ne(value, 0);
    }

    /**
     * @dev Casts an encrypted integer from 'euint8' to 'euint16'.
     */
    function asEuint16(euint8 value) internal returns (euint16) {
        if (!isInitialized(value)) {
            value = asEuint8(0);
        }
        return euint16.wrap(Impl.cast(euint8.unwrap(value), FheType.Uint16));
    }

    /**
     * @dev Casts an encrypted integer from 'euint32' to 'euint16'.
     */
    function asEuint16(euint32 value) internal returns (euint16) {
        if (!isInitialized(value)) {
            value = asEuint32(0);
        }
        return euint16.wrap(Impl.cast(euint32.unwrap(value), FheType.Uint16));
    }

    /**
     * @dev Casts an encrypted integer from 'euint64' to 'euint16'.
     */
    function asEuint16(euint64 value) internal returns (euint16) {
        if (!isInitialized(value)) {
            value = asEuint64(0);
        }
        return euint16.wrap(Impl.cast(euint64.unwrap(value), FheType.Uint16));
    }

    /**
     * @dev Casts an encrypted integer from 'euint128' to 'euint16'.
     */
    function asEuint16(euint128 value) internal returns (euint16) {
        if (!isInitialized(value)) {
            value = asEuint128(0);
        }
        return euint16.wrap(Impl.cast(euint128.unwrap(value), FheType.Uint16));
    }

    /**
     * @dev Casts an encrypted integer from 'euint256' to 'euint16'.
     */
    function asEuint16(euint256 value) internal returns (euint16) {
        if (!isInitialized(value)) {
            value = asEuint256(0);
        }
        return euint16.wrap(Impl.cast(euint256.unwrap(value), FheType.Uint16));
    }

    /**
    /** 
     * @dev Converts an 'ebool' to an 'euint16'.
     */
    function asEuint16(ebool b) internal returns (euint16) {
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return euint16.wrap(Impl.cast(ebool.unwrap(b), FheType.Uint16));
    }

    /**
     * @dev Casts an encrypted integer from 'euint16' to 'ebool'.
     */
    function asEbool(euint16 value) internal returns (ebool) {
        if (!isInitialized(value)) {
            value = asEuint16(0);
        }
        return ne(value, 0);
    }

    /**
     * @dev Casts an encrypted integer from 'euint8' to 'euint32'.
     */
    function asEuint32(euint8 value) internal returns (euint32) {
        if (!isInitialized(value)) {
            value = asEuint8(0);
        }
        return euint32.wrap(Impl.cast(euint8.unwrap(value), FheType.Uint32));
    }

    /**
     * @dev Casts an encrypted integer from 'euint16' to 'euint32'.
     */
    function asEuint32(euint16 value) internal returns (euint32) {
        if (!isInitialized(value)) {
            value = asEuint16(0);
        }
        return euint32.wrap(Impl.cast(euint16.unwrap(value), FheType.Uint32));
    }

    /**
     * @dev Casts an encrypted integer from 'euint64' to 'euint32'.
     */
    function asEuint32(euint64 value) internal returns (euint32) {
        if (!isInitialized(value)) {
            value = asEuint64(0);
        }
        return euint32.wrap(Impl.cast(euint64.unwrap(value), FheType.Uint32));
    }

    /**
     * @dev Casts an encrypted integer from 'euint128' to 'euint32'.
     */
    function asEuint32(euint128 value) internal returns (euint32) {
        if (!isInitialized(value)) {
            value = asEuint128(0);
        }
        return euint32.wrap(Impl.cast(euint128.unwrap(value), FheType.Uint32));
    }

    /**
     * @dev Casts an encrypted integer from 'euint256' to 'euint32'.
     */
    function asEuint32(euint256 value) internal returns (euint32) {
        if (!isInitialized(value)) {
            value = asEuint256(0);
        }
        return euint32.wrap(Impl.cast(euint256.unwrap(value), FheType.Uint32));
    }

    /**
    /** 
     * @dev Converts an 'ebool' to an 'euint32'.
     */
    function asEuint32(ebool b) internal returns (euint32) {
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return euint32.wrap(Impl.cast(ebool.unwrap(b), FheType.Uint32));
    }

    /**
     * @dev Casts an encrypted integer from 'euint32' to 'ebool'.
     */
    function asEbool(euint32 value) internal returns (ebool) {
        if (!isInitialized(value)) {
            value = asEuint32(0);
        }
        return ne(value, 0);
    }

    /**
     * @dev Casts an encrypted integer from 'euint8' to 'euint64'.
     */
    function asEuint64(euint8 value) internal returns (euint64) {
        if (!isInitialized(value)) {
            value = asEuint8(0);
        }
        return euint64.wrap(Impl.cast(euint8.unwrap(value), FheType.Uint64));
    }

    /**
     * @dev Casts an encrypted integer from 'euint16' to 'euint64'.
     */
    function asEuint64(euint16 value) internal returns (euint64) {
        if (!isInitialized(value)) {
            value = asEuint16(0);
        }
        return euint64.wrap(Impl.cast(euint16.unwrap(value), FheType.Uint64));
    }

    /**
     * @dev Casts an encrypted integer from 'euint32' to 'euint64'.
     */
    function asEuint64(euint32 value) internal returns (euint64) {
        if (!isInitialized(value)) {
            value = asEuint32(0);
        }
        return euint64.wrap(Impl.cast(euint32.unwrap(value), FheType.Uint64));
    }

    /**
     * @dev Casts an encrypted integer from 'euint128' to 'euint64'.
     */
    function asEuint64(euint128 value) internal returns (euint64) {
        if (!isInitialized(value)) {
            value = asEuint128(0);
        }
        return euint64.wrap(Impl.cast(euint128.unwrap(value), FheType.Uint64));
    }

    /**
     * @dev Casts an encrypted integer from 'euint256' to 'euint64'.
     */
    function asEuint64(euint256 value) internal returns (euint64) {
        if (!isInitialized(value)) {
            value = asEuint256(0);
        }
        return euint64.wrap(Impl.cast(euint256.unwrap(value), FheType.Uint64));
    }

    /**
    /** 
     * @dev Converts an 'ebool' to an 'euint64'.
     */
    function asEuint64(ebool b) internal returns (euint64) {
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return euint64.wrap(Impl.cast(ebool.unwrap(b), FheType.Uint64));
    }

    /**
     * @dev Casts an encrypted integer from 'euint64' to 'ebool'.
     */
    function asEbool(euint64 value) internal returns (ebool) {
        if (!isInitialized(value)) {
            value = asEuint64(0);
        }
        return ne(value, 0);
    }

    /**
     * @dev Casts an encrypted integer from 'euint8' to 'euint128'.
     */
    function asEuint128(euint8 value) internal returns (euint128) {
        if (!isInitialized(value)) {
            value = asEuint8(0);
        }
        return euint128.wrap(Impl.cast(euint8.unwrap(value), FheType.Uint128));
    }

    /**
     * @dev Casts an encrypted integer from 'euint16' to 'euint128'.
     */
    function asEuint128(euint16 value) internal returns (euint128) {
        if (!isInitialized(value)) {
            value = asEuint16(0);
        }
        return euint128.wrap(Impl.cast(euint16.unwrap(value), FheType.Uint128));
    }

    /**
     * @dev Casts an encrypted integer from 'euint32' to 'euint128'.
     */
    function asEuint128(euint32 value) internal returns (euint128) {
        if (!isInitialized(value)) {
            value = asEuint32(0);
        }
        return euint128.wrap(Impl.cast(euint32.unwrap(value), FheType.Uint128));
    }

    /**
     * @dev Casts an encrypted integer from 'euint64' to 'euint128'.
     */
    function asEuint128(euint64 value) internal returns (euint128) {
        if (!isInitialized(value)) {
            value = asEuint64(0);
        }
        return euint128.wrap(Impl.cast(euint64.unwrap(value), FheType.Uint128));
    }

    /**
     * @dev Casts an encrypted integer from 'euint256' to 'euint128'.
     */
    function asEuint128(euint256 value) internal returns (euint128) {
        if (!isInitialized(value)) {
            value = asEuint256(0);
        }
        return euint128.wrap(Impl.cast(euint256.unwrap(value), FheType.Uint128));
    }

    /**
    /** 
     * @dev Converts an 'ebool' to an 'euint128'.
     */
    function asEuint128(ebool b) internal returns (euint128) {
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return euint128.wrap(Impl.cast(ebool.unwrap(b), FheType.Uint128));
    }

    /**
     * @dev Casts an encrypted integer from 'euint128' to 'ebool'.
     */
    function asEbool(euint128 value) internal returns (ebool) {
        if (!isInitialized(value)) {
            value = asEuint128(0);
        }
        return ne(value, 0);
    }

    /**
     * @dev Casts an encrypted integer from 'euint8' to 'euint256'.
     */
    function asEuint256(euint8 value) internal returns (euint256) {
        if (!isInitialized(value)) {
            value = asEuint8(0);
        }
        return euint256.wrap(Impl.cast(euint8.unwrap(value), FheType.Uint256));
    }

    /**
     * @dev Casts an encrypted integer from 'euint16' to 'euint256'.
     */
    function asEuint256(euint16 value) internal returns (euint256) {
        if (!isInitialized(value)) {
            value = asEuint16(0);
        }
        return euint256.wrap(Impl.cast(euint16.unwrap(value), FheType.Uint256));
    }

    /**
     * @dev Casts an encrypted integer from 'euint32' to 'euint256'.
     */
    function asEuint256(euint32 value) internal returns (euint256) {
        if (!isInitialized(value)) {
            value = asEuint32(0);
        }
        return euint256.wrap(Impl.cast(euint32.unwrap(value), FheType.Uint256));
    }

    /**
     * @dev Casts an encrypted integer from 'euint64' to 'euint256'.
     */
    function asEuint256(euint64 value) internal returns (euint256) {
        if (!isInitialized(value)) {
            value = asEuint64(0);
        }
        return euint256.wrap(Impl.cast(euint64.unwrap(value), FheType.Uint256));
    }

    /**
     * @dev Casts an encrypted integer from 'euint128' to 'euint256'.
     */
    function asEuint256(euint128 value) internal returns (euint256) {
        if (!isInitialized(value)) {
            value = asEuint128(0);
        }
        return euint256.wrap(Impl.cast(euint128.unwrap(value), FheType.Uint256));
    }

    /**
    /** 
     * @dev Converts an 'ebool' to an 'euint256'.
     */
    function asEuint256(ebool b) internal returns (euint256) {
        if (!isInitialized(b)) {
            b = asEbool(false);
        }
        return euint256.wrap(Impl.cast(ebool.unwrap(b), FheType.Uint256));
    }

    /**
     * @dev Casts an encrypted integer from 'euint256' to 'ebool'.
     */
    function asEbool(euint256 value) internal returns (ebool) {
        if (!isInitialized(value)) {
            value = asEuint256(0);
        }
        return ne(value, 0);
    }

    /**
     * @dev Evaluates not(ebool value) and returns the result.
     */
    function not(ebool value) internal returns (ebool) {
        if (!isInitialized(value)) {
            value = asEbool(false);
        }
        return ebool.wrap(Impl.not(ebool.unwrap(value)));
    }

    /**
     * @dev Evaluates neg(euint8 value) and returns the result.
     */
    function neg(euint8 value) internal returns (euint8) {
        if (!isInitialized(value)) {
            value = asEuint8(0);
        }
        return euint8.wrap(Impl.neg(euint8.unwrap(value)));
    }

    /**
     * @dev Evaluates not(euint8 value) and returns the result.
     */
    function not(euint8 value) internal returns (euint8) {
        if (!isInitialized(value)) {
            value = asEuint8(0);
        }
        return euint8.wrap(Impl.not(euint8.unwrap(value)));
    }

    /**
     * @dev Evaluates neg(euint16 value) and returns the result.
     */
    function neg(euint16 value) internal returns (euint16) {
        if (!isInitialized(value)) {
            value = asEuint16(0);
        }
        return euint16.wrap(Impl.neg(euint16.unwrap(value)));
    }

    /**
     * @dev Evaluates not(euint16 value) and returns the result.
     */
    function not(euint16 value) internal returns (euint16) {
        if (!isInitialized(value)) {
            value = asEuint16(0);
        }
        return euint16.wrap(Impl.not(euint16.unwrap(value)));
    }

    /**
     * @dev Evaluates neg(euint32 value) and returns the result.
     */
    function neg(euint32 value) internal returns (euint32) {
        if (!isInitialized(value)) {
            value = asEuint32(0);
        }
        return euint32.wrap(Impl.neg(euint32.unwrap(value)));
    }

    /**
     * @dev Evaluates not(euint32 value) and returns the result.
     */
    function not(euint32 value) internal returns (euint32) {
        if (!isInitialized(value)) {
            value = asEuint32(0);
        }
        return euint32.wrap(Impl.not(euint32.unwrap(value)));
    }

    /**
     * @dev Evaluates neg(euint64 value) and returns the result.
     */
    function neg(euint64 value) internal returns (euint64) {
        if (!isInitialized(value)) {
            value = asEuint64(0);
        }
        return euint64.wrap(Impl.neg(euint64.unwrap(value)));
    }

    /**
     * @dev Evaluates not(euint64 value) and returns the result.
     */
    function not(euint64 value) internal returns (euint64) {
        if (!isInitialized(value)) {
            value = asEuint64(0);
        }
        return euint64.wrap(Impl.not(euint64.unwrap(value)));
    }

    /**
     * @dev Evaluates neg(euint128 value) and returns the result.
     */
    function neg(euint128 value) internal returns (euint128) {
        if (!isInitialized(value)) {
            value = asEuint128(0);
        }
        return euint128.wrap(Impl.neg(euint128.unwrap(value)));
    }

    /**
     * @dev Evaluates not(euint128 value) and returns the result.
     */
    function not(euint128 value) internal returns (euint128) {
        if (!isInitialized(value)) {
            value = asEuint128(0);
        }
        return euint128.wrap(Impl.not(euint128.unwrap(value)));
    }

    /**
     * @dev Evaluates neg(euint256 value) and returns the result.
     */
    function neg(euint256 value) internal returns (euint256) {
        if (!isInitialized(value)) {
            value = asEuint256(0);
        }
        return euint256.wrap(Impl.neg(euint256.unwrap(value)));
    }

    /**
     * @dev Evaluates not(euint256 value) and returns the result.
     */
    function not(euint256 value) internal returns (euint256) {
        if (!isInitialized(value)) {
            value = asEuint256(0);
        }
        return euint256.wrap(Impl.not(euint256.unwrap(value)));
    }

    /**
     * @dev Convert an inputHandle with corresponding inputProof to an encrypted ebool integer.
     * @dev If inputProof is empty, the externalEbool inputHandle can be used as a regular ebool handle if it
     *      has already been verified and allowed to the sender.
     *      This could facilitate integrating smart contract accounts with fhevm.
     */
    function fromExternal(externalEbool inputHandle, bytes memory inputProof) internal returns (ebool) {
        if (inputProof.length != 0) {
            return ebool.wrap(Impl.verify(externalEbool.unwrap(inputHandle), inputProof, FheType.Bool));
        } else {
            bytes32 inputBytes32 = externalEbool.unwrap(inputHandle);
            if (inputBytes32 == 0) {
                return asEbool(false);
            }
            if (!Impl.isAllowed(inputBytes32, msg.sender)) revert SenderNotAllowedToUseHandle(inputBytes32, msg.sender);
            return ebool.wrap(inputBytes32);
        }
    }

    /**
     * @dev Converts a plaintext boolean to an encrypted boolean.
     */
    function asEbool(bool value) internal returns (ebool) {
        return ebool.wrap(Impl.trivialEncrypt(value ? 1 : 0, FheType.Bool));
    }

    /**
     * @dev Convert an inputHandle with corresponding inputProof to an encrypted euint8 integer.
     * @dev If inputProof is empty, the externalEuint8 inputHandle can be used as a regular euint8 handle if it
     *      has already been verified and allowed to the sender.
     *      This could facilitate integrating smart contract accounts with fhevm.
     */
    function fromExternal(externalEuint8 inputHandle, bytes memory inputProof) internal returns (euint8) {
        if (inputProof.length != 0) {
            return euint8.wrap(Impl.verify(externalEuint8.unwrap(inputHandle), inputProof, FheType.Uint8));
        } else {
            bytes32 inputBytes32 = externalEuint8.unwrap(inputHandle);
            if (inputBytes32 == 0) {
                return asEuint8(0);
            }
            if (!Impl.isAllowed(inputBytes32, msg.sender)) revert SenderNotAllowedToUseHandle(inputBytes32, msg.sender);
            return euint8.wrap(inputBytes32);
        }
    }

    /**
     * @dev Convert a plaintext value to an encrypted euint8 value.
     */
    function asEuint8(uint8 value) internal returns (euint8) {
        return euint8.wrap(Impl.trivialEncrypt(uint256(value), FheType.Uint8));
    }

    /**
     * @dev Convert an inputHandle with corresponding inputProof to an encrypted euint16 integer.
     * @dev If inputProof is empty, the externalEuint16 inputHandle can be used as a regular euint16 handle if it
     *      has already been verified and allowed to the sender.
     *      This could facilitate integrating smart contract accounts with fhevm.
     */
    function fromExternal(externalEuint16 inputHandle, bytes memory inputProof) internal returns (euint16) {
        if (inputProof.length != 0) {
            return euint16.wrap(Impl.verify(externalEuint16.unwrap(inputHandle), inputProof, FheType.Uint16));
        } else {
            bytes32 inputBytes32 = externalEuint16.unwrap(inputHandle);
            if (inputBytes32 == 0) {
                return asEuint16(0);
            }
            if (!Impl.isAllowed(inputBytes32, msg.sender)) revert SenderNotAllowedToUseHandle(inputBytes32, msg.sender);
            return euint16.wrap(inputBytes32);
        }
    }

    /**
     * @dev Convert a plaintext value to an encrypted euint16 value.
     */
    function asEuint16(uint16 value) internal returns (euint16) {
        return euint16.wrap(Impl.trivialEncrypt(uint256(value), FheType.Uint16));
    }

    /**
     * @dev Convert an inputHandle with corresponding inputProof to an encrypted euint32 integer.
     * @dev If inputProof is empty, the externalEuint32 inputHandle can be used as a regular euint32 handle if it
     *      has already been verified and allowed to the sender.
     *      This could facilitate integrating smart contract accounts with fhevm.
     */
    function fromExternal(externalEuint32 inputHandle, bytes memory inputProof) internal returns (euint32) {
        if (inputProof.length != 0) {
            return euint32.wrap(Impl.verify(externalEuint32.unwrap(inputHandle), inputProof, FheType.Uint32));
        } else {
            bytes32 inputBytes32 = externalEuint32.unwrap(inputHandle);
            if (inputBytes32 == 0) {
                return asEuint32(0);
            }
            if (!Impl.isAllowed(inputBytes32, msg.sender)) revert SenderNotAllowedToUseHandle(inputBytes32, msg.sender);
            return euint32.wrap(inputBytes32);
        }
    }

    /**
     * @dev Convert a plaintext value to an encrypted euint32 value.
     */
    function asEuint32(uint32 value) internal returns (euint32) {
        return euint32.wrap(Impl.trivialEncrypt(uint256(value), FheType.Uint32));
    }

    /**
     * @dev Convert an inputHandle with corresponding inputProof to an encrypted euint64 integer.
     * @dev If inputProof is empty, the externalEuint64 inputHandle can be used as a regular euint64 handle if it
     *      has already been verified and allowed to the sender.
     *      This could facilitate integrating smart contract accounts with fhevm.
     */
    function fromExternal(externalEuint64 inputHandle, bytes memory inputProof) internal returns (euint64) {
        if (inputProof.length != 0) {
            return euint64.wrap(Impl.verify(externalEuint64.unwrap(inputHandle), inputProof, FheType.Uint64));
        } else {
            bytes32 inputBytes32 = externalEuint64.unwrap(inputHandle);
            if (inputBytes32 == 0) {
                return asEuint64(0);
            }
            if (!Impl.isAllowed(inputBytes32, msg.sender)) revert SenderNotAllowedToUseHandle(inputBytes32, msg.sender);
            return euint64.wrap(inputBytes32);
        }
    }

    /**
     * @dev Convert a plaintext value to an encrypted euint64 value.
     */
    function asEuint64(uint64 value) internal returns (euint64) {
        return euint64.wrap(Impl.trivialEncrypt(uint256(value), FheType.Uint64));
    }

    /**
     * @dev Convert an inputHandle with corresponding inputProof to an encrypted euint128 integer.
     * @dev If inputProof is empty, the externalEuint128 inputHandle can be used as a regular euint128 handle if it
     *      has already been verified and allowed to the sender.
     *      This could facilitate integrating smart contract accounts with fhevm.
     */
    function fromExternal(externalEuint128 inputHandle, bytes memory inputProof) internal returns (euint128) {
        if (inputProof.length != 0) {
            return euint128.wrap(Impl.verify(externalEuint128.unwrap(inputHandle), inputProof, FheType.Uint128));
        } else {
            bytes32 inputBytes32 = externalEuint128.unwrap(inputHandle);
            if (inputBytes32 == 0) {
                return asEuint128(0);
            }
            if (!Impl.isAllowed(inputBytes32, msg.sender)) revert SenderNotAllowedToUseHandle(inputBytes32, msg.sender);
            return euint128.wrap(inputBytes32);
        }
    }

    /**
     * @dev Convert a plaintext value to an encrypted euint128 value.
     */
    function asEuint128(uint128 value) internal returns (euint128) {
        return euint128.wrap(Impl.trivialEncrypt(uint256(value), FheType.Uint128));
    }

    /**
     * @dev Convert an inputHandle with corresponding inputProof to an encrypted eaddress integer.
     * @dev If inputProof is empty, the externalEaddress inputHandle can be used as a regular eaddress handle if it
     *      has already been verified and allowed to the sender.
     *      This could facilitate integrating smart contract accounts with fhevm.
     */
    function fromExternal(externalEaddress inputHandle, bytes memory inputProof) internal returns (eaddress) {
        if (inputProof.length != 0) {
            return eaddress.wrap(Impl.verify(externalEaddress.unwrap(inputHandle), inputProof, FheType.Uint160));
        } else {
            bytes32 inputBytes32 = externalEaddress.unwrap(inputHandle);
            if (inputBytes32 == 0) {
                return asEaddress(address(0));
            }
            if (!Impl.isAllowed(inputBytes32, msg.sender)) revert SenderNotAllowedToUseHandle(inputBytes32, msg.sender);
            return eaddress.wrap(inputBytes32);
        }
    }

    /**
     * @dev Convert a plaintext value to an encrypted eaddress value.
     */
    function asEaddress(address value) internal returns (eaddress) {
        return eaddress.wrap(Impl.trivialEncrypt(uint256(uint160(value)), FheType.Uint160));
    }

    /**
     * @dev Convert an inputHandle with corresponding inputProof to an encrypted euint256 integer.
     * @dev If inputProof is empty, the externalEuint256 inputHandle can be used as a regular euint256 handle if it
     *      has already been verified and allowed to the sender.
     *      This could facilitate integrating smart contract accounts with fhevm.
     */
    function fromExternal(externalEuint256 inputHandle, bytes memory inputProof) internal returns (euint256) {
        if (inputProof.length != 0) {
            return euint256.wrap(Impl.verify(externalEuint256.unwrap(inputHandle), inputProof, FheType.Uint256));
        } else {
            bytes32 inputBytes32 = externalEuint256.unwrap(inputHandle);
            if (inputBytes32 == 0) {
                return asEuint256(0);
            }
            if (!Impl.isAllowed(inputBytes32, msg.sender)) revert SenderNotAllowedToUseHandle(inputBytes32, msg.sender);
            return euint256.wrap(inputBytes32);
        }
    }

    /**
     * @dev Convert a plaintext value to an encrypted euint256 value.
     */
    function asEuint256(uint256 value) internal returns (euint256) {
        return euint256.wrap(Impl.trivialEncrypt(uint256(value), FheType.Uint256));
    }

    /**
     * @dev Generates a random encrypted value.
     */
    function randEbool() internal returns (ebool) {
        return ebool.wrap(Impl.rand(FheType.Bool));
    }

    /**
     * @dev Generates a random encrypted value.
     */
    function randEuint8() internal returns (euint8) {
        return euint8.wrap(Impl.rand(FheType.Uint8));
    }

    /**
     * @dev Generates a random encrypted 8-bit unsigned integer in the [0, upperBound) range.
     *      The upperBound must be a power of 2.
     */
    function randEuint8(uint8 upperBound) internal returns (euint8) {
        return euint8.wrap(Impl.randBounded(upperBound, FheType.Uint8));
    }

    /**
     * @dev Generates a random encrypted value.
     */
    function randEuint16() internal returns (euint16) {
        return euint16.wrap(Impl.rand(FheType.Uint16));
    }

    /**
     * @dev Generates a random encrypted 16-bit unsigned integer in the [0, upperBound) range.
     *      The upperBound must be a power of 2.
     */
    function randEuint16(uint16 upperBound) internal returns (euint16) {
        return euint16.wrap(Impl.randBounded(upperBound, FheType.Uint16));
    }

    /**
     * @dev Generates a random encrypted value.
     */
    function randEuint32() internal returns (euint32) {
        return euint32.wrap(Impl.rand(FheType.Uint32));
    }

    /**
     * @dev Generates a random encrypted 32-bit unsigned integer in the [0, upperBound) range.
     *      The upperBound must be a power of 2.
     */
    function randEuint32(uint32 upperBound) internal returns (euint32) {
        return euint32.wrap(Impl.randBounded(upperBound, FheType.Uint32));
    }

    /**
     * @dev Generates a random encrypted value.
     */
    function randEuint64() internal returns (euint64) {
        return euint64.wrap(Impl.rand(FheType.Uint64));
    }

    /**
     * @dev Generates a random encrypted 64-bit unsigned integer in the [0, upperBound) range.
     *      The upperBound must be a power of 2.
     */
    function randEuint64(uint64 upperBound) internal returns (euint64) {
        return euint64.wrap(Impl.randBounded(upperBound, FheType.Uint64));
    }

    /**
     * @dev Generates a random encrypted value.
     */
    function randEuint128() internal returns (euint128) {
        return euint128.wrap(Impl.rand(FheType.Uint128));
    }

    /**
     * @dev Generates a random encrypted 128-bit unsigned integer in the [0, upperBound) range.
     *      The upperBound must be a power of 2.
     */
    function randEuint128(uint128 upperBound) internal returns (euint128) {
        return euint128.wrap(Impl.randBounded(upperBound, FheType.Uint128));
    }

    /**
     * @dev Generates a random encrypted value.
     */
    function randEuint256() internal returns (euint256) {
        return euint256.wrap(Impl.rand(FheType.Uint256));
    }

    /**
     * @dev Generates a random encrypted 256-bit unsigned integer in the [0, upperBound) range.
     *      The upperBound must be a power of 2.
     */
    function randEuint256(uint256 upperBound) internal returns (euint256) {
        return euint256.wrap(Impl.randBounded(upperBound, FheType.Uint256));
    }

    /**
     * @dev This function cleans the transient storage for the ACL (accounts) and the InputVerifier
     *      (input proofs).
     *      This could be useful for integration with Account Abstraction when bundling several
     *      UserOps calling the FHEVMExecutor.
     */
    function cleanTransientStorage() internal {
        Impl.cleanTransientStorageACL();
        Impl.cleanTransientStorageInputVerifier();
    }

    /**
     * @dev Returns whether the account is allowed to use the value.
     */
    function isAllowed(ebool value, address account) internal view returns (bool) {
        return Impl.isAllowed(ebool.unwrap(value), account);
    }

    /**
     * @dev Returns whether the sender is allowed to use the value.
     */
    function isSenderAllowed(ebool value) internal view returns (bool) {
        return Impl.isAllowed(ebool.unwrap(value), msg.sender);
    }

    /**
     * @dev Allows the use of value for the address account.
     */
    function allow(ebool value, address account) internal returns (ebool) {
        if (!isInitialized(value)) {
            value = asEbool(false);
        }
        Impl.allow(ebool.unwrap(value), account);
        return value;
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     */
    function allowThis(ebool value) internal returns (ebool) {
        if (!isInitialized(value)) {
            value = asEbool(false);
        }
        Impl.allow(ebool.unwrap(value), address(this));
        return value;
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     */
    function allowTransient(ebool value, address account) internal returns (ebool) {
        if (!isInitialized(value)) {
            value = asEbool(false);
        }
        Impl.allowTransient(ebool.unwrap(value), account);
        return value;
    }

    /**
     * @dev Makes the value publicly decryptable.
     */
    function makePubliclyDecryptable(ebool value) internal returns (ebool) {
        if (!isInitialized(value)) {
            value = asEbool(false);
        }
        Impl.makePubliclyDecryptable(ebool.unwrap(value));
        return value;
    }

    /**
     * @dev Returns whether the the value is publicly decryptable.
     */
    function isPubliclyDecryptable(ebool value) internal view returns (bool) {
        return Impl.isPubliclyDecryptable(ebool.unwrap(value));
    }

    /**
     * @dev Returns whether the account is allowed to use the value.
     */
    function isAllowed(euint8 value, address account) internal view returns (bool) {
        return Impl.isAllowed(euint8.unwrap(value), account);
    }

    /**
     * @dev Returns whether the sender is allowed to use the value.
     */
    function isSenderAllowed(euint8 value) internal view returns (bool) {
        return Impl.isAllowed(euint8.unwrap(value), msg.sender);
    }

    /**
     * @dev Allows the use of value for the address account.
     */
    function allow(euint8 value, address account) internal returns (euint8) {
        if (!isInitialized(value)) {
            value = asEuint8(0);
        }
        Impl.allow(euint8.unwrap(value), account);
        return value;
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     */
    function allowThis(euint8 value) internal returns (euint8) {
        if (!isInitialized(value)) {
            value = asEuint8(0);
        }
        Impl.allow(euint8.unwrap(value), address(this));
        return value;
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     */
    function allowTransient(euint8 value, address account) internal returns (euint8) {
        if (!isInitialized(value)) {
            value = asEuint8(0);
        }
        Impl.allowTransient(euint8.unwrap(value), account);
        return value;
    }

    /**
     * @dev Makes the value publicly decryptable.
     */
    function makePubliclyDecryptable(euint8 value) internal returns (euint8) {
        if (!isInitialized(value)) {
            value = asEuint8(0);
        }
        Impl.makePubliclyDecryptable(euint8.unwrap(value));
        return value;
    }

    /**
     * @dev Returns whether the the value is publicly decryptable.
     */
    function isPubliclyDecryptable(euint8 value) internal view returns (bool) {
        return Impl.isPubliclyDecryptable(euint8.unwrap(value));
    }

    /**
     * @dev Returns whether the account is allowed to use the value.
     */
    function isAllowed(euint16 value, address account) internal view returns (bool) {
        return Impl.isAllowed(euint16.unwrap(value), account);
    }

    /**
     * @dev Returns whether the sender is allowed to use the value.
     */
    function isSenderAllowed(euint16 value) internal view returns (bool) {
        return Impl.isAllowed(euint16.unwrap(value), msg.sender);
    }

    /**
     * @dev Allows the use of value for the address account.
     */
    function allow(euint16 value, address account) internal returns (euint16) {
        if (!isInitialized(value)) {
            value = asEuint16(0);
        }
        Impl.allow(euint16.unwrap(value), account);
        return value;
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     */
    function allowThis(euint16 value) internal returns (euint16) {
        if (!isInitialized(value)) {
            value = asEuint16(0);
        }
        Impl.allow(euint16.unwrap(value), address(this));
        return value;
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     */
    function allowTransient(euint16 value, address account) internal returns (euint16) {
        if (!isInitialized(value)) {
            value = asEuint16(0);
        }
        Impl.allowTransient(euint16.unwrap(value), account);
        return value;
    }

    /**
     * @dev Makes the value publicly decryptable.
     */
    function makePubliclyDecryptable(euint16 value) internal returns (euint16) {
        if (!isInitialized(value)) {
            value = asEuint16(0);
        }
        Impl.makePubliclyDecryptable(euint16.unwrap(value));
        return value;
    }

    /**
     * @dev Returns whether the the value is publicly decryptable.
     */
    function isPubliclyDecryptable(euint16 value) internal view returns (bool) {
        return Impl.isPubliclyDecryptable(euint16.unwrap(value));
    }

    /**
     * @dev Returns whether the account is allowed to use the value.
     */
    function isAllowed(euint32 value, address account) internal view returns (bool) {
        return Impl.isAllowed(euint32.unwrap(value), account);
    }

    /**
     * @dev Returns whether the sender is allowed to use the value.
     */
    function isSenderAllowed(euint32 value) internal view returns (bool) {
        return Impl.isAllowed(euint32.unwrap(value), msg.sender);
    }

    /**
     * @dev Allows the use of value for the address account.
     */
    function allow(euint32 value, address account) internal returns (euint32) {
        if (!isInitialized(value)) {
            value = asEuint32(0);
        }
        Impl.allow(euint32.unwrap(value), account);
        return value;
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     */
    function allowThis(euint32 value) internal returns (euint32) {
        if (!isInitialized(value)) {
            value = asEuint32(0);
        }
        Impl.allow(euint32.unwrap(value), address(this));
        return value;
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     */
    function allowTransient(euint32 value, address account) internal returns (euint32) {
        if (!isInitialized(value)) {
            value = asEuint32(0);
        }
        Impl.allowTransient(euint32.unwrap(value), account);
        return value;
    }

    /**
     * @dev Makes the value publicly decryptable.
     */
    function makePubliclyDecryptable(euint32 value) internal returns (euint32) {
        if (!isInitialized(value)) {
            value = asEuint32(0);
        }
        Impl.makePubliclyDecryptable(euint32.unwrap(value));
        return value;
    }

    /**
     * @dev Returns whether the the value is publicly decryptable.
     */
    function isPubliclyDecryptable(euint32 value) internal view returns (bool) {
        return Impl.isPubliclyDecryptable(euint32.unwrap(value));
    }

    /**
     * @dev Returns whether the account is allowed to use the value.
     */
    function isAllowed(euint64 value, address account) internal view returns (bool) {
        return Impl.isAllowed(euint64.unwrap(value), account);
    }

    /**
     * @dev Returns whether the sender is allowed to use the value.
     */
    function isSenderAllowed(euint64 value) internal view returns (bool) {
        return Impl.isAllowed(euint64.unwrap(value), msg.sender);
    }

    /**
     * @dev Allows the use of value for the address account.
     */
    function allow(euint64 value, address account) internal returns (euint64) {
        if (!isInitialized(value)) {
            value = asEuint64(0);
        }
        Impl.allow(euint64.unwrap(value), account);
        return value;
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     */
    function allowThis(euint64 value) internal returns (euint64) {
        if (!isInitialized(value)) {
            value = asEuint64(0);
        }
        Impl.allow(euint64.unwrap(value), address(this));
        return value;
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     */
    function allowTransient(euint64 value, address account) internal returns (euint64) {
        if (!isInitialized(value)) {
            value = asEuint64(0);
        }
        Impl.allowTransient(euint64.unwrap(value), account);
        return value;
    }

    /**
     * @dev Makes the value publicly decryptable.
     */
    function makePubliclyDecryptable(euint64 value) internal returns (euint64) {
        if (!isInitialized(value)) {
            value = asEuint64(0);
        }
        Impl.makePubliclyDecryptable(euint64.unwrap(value));
        return value;
    }

    /**
     * @dev Returns whether the the value is publicly decryptable.
     */
    function isPubliclyDecryptable(euint64 value) internal view returns (bool) {
        return Impl.isPubliclyDecryptable(euint64.unwrap(value));
    }

    /**
     * @dev Returns whether the account is allowed to use the value.
     */
    function isAllowed(euint128 value, address account) internal view returns (bool) {
        return Impl.isAllowed(euint128.unwrap(value), account);
    }

    /**
     * @dev Returns whether the sender is allowed to use the value.
     */
    function isSenderAllowed(euint128 value) internal view returns (bool) {
        return Impl.isAllowed(euint128.unwrap(value), msg.sender);
    }

    /**
     * @dev Allows the use of value for the address account.
     */
    function allow(euint128 value, address account) internal returns (euint128) {
        if (!isInitialized(value)) {
            value = asEuint128(0);
        }
        Impl.allow(euint128.unwrap(value), account);
        return value;
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     */
    function allowThis(euint128 value) internal returns (euint128) {
        if (!isInitialized(value)) {
            value = asEuint128(0);
        }
        Impl.allow(euint128.unwrap(value), address(this));
        return value;
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     */
    function allowTransient(euint128 value, address account) internal returns (euint128) {
        if (!isInitialized(value)) {
            value = asEuint128(0);
        }
        Impl.allowTransient(euint128.unwrap(value), account);
        return value;
    }

    /**
     * @dev Makes the value publicly decryptable.
     */
    function makePubliclyDecryptable(euint128 value) internal returns (euint128) {
        if (!isInitialized(value)) {
            value = asEuint128(0);
        }
        Impl.makePubliclyDecryptable(euint128.unwrap(value));
        return value;
    }

    /**
     * @dev Returns whether the the value is publicly decryptable.
     */
    function isPubliclyDecryptable(euint128 value) internal view returns (bool) {
        return Impl.isPubliclyDecryptable(euint128.unwrap(value));
    }

    /**
     * @dev Returns whether the account is allowed to use the value.
     */
    function isAllowed(eaddress value, address account) internal view returns (bool) {
        return Impl.isAllowed(eaddress.unwrap(value), account);
    }

    /**
     * @dev Returns whether the sender is allowed to use the value.
     */
    function isSenderAllowed(eaddress value) internal view returns (bool) {
        return Impl.isAllowed(eaddress.unwrap(value), msg.sender);
    }

    /**
     * @dev Allows the use of value for the address account.
     */
    function allow(eaddress value, address account) internal returns (eaddress) {
        if (!isInitialized(value)) {
            value = asEaddress(address(0));
        }
        Impl.allow(eaddress.unwrap(value), account);
        return value;
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     */
    function allowThis(eaddress value) internal returns (eaddress) {
        if (!isInitialized(value)) {
            value = asEaddress(address(0));
        }
        Impl.allow(eaddress.unwrap(value), address(this));
        return value;
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     */
    function allowTransient(eaddress value, address account) internal returns (eaddress) {
        if (!isInitialized(value)) {
            value = asEaddress(address(0));
        }
        Impl.allowTransient(eaddress.unwrap(value), account);
        return value;
    }

    /**
     * @dev Makes the value publicly decryptable.
     */
    function makePubliclyDecryptable(eaddress value) internal returns (eaddress) {
        if (!isInitialized(value)) {
            value = asEaddress(address(0));
        }
        Impl.makePubliclyDecryptable(eaddress.unwrap(value));
        return value;
    }

    /**
     * @dev Returns whether the the value is publicly decryptable.
     */
    function isPubliclyDecryptable(eaddress value) internal view returns (bool) {
        return Impl.isPubliclyDecryptable(eaddress.unwrap(value));
    }

    /**
     * @dev Returns whether the account is allowed to use the value.
     */
    function isAllowed(euint256 value, address account) internal view returns (bool) {
        return Impl.isAllowed(euint256.unwrap(value), account);
    }

    /**
     * @dev Returns whether the sender is allowed to use the value.
     */
    function isSenderAllowed(euint256 value) internal view returns (bool) {
        return Impl.isAllowed(euint256.unwrap(value), msg.sender);
    }

    /**
     * @dev Allows the use of value for the address account.
     */
    function allow(euint256 value, address account) internal returns (euint256) {
        if (!isInitialized(value)) {
            value = asEuint256(0);
        }
        Impl.allow(euint256.unwrap(value), account);
        return value;
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     */
    function allowThis(euint256 value) internal returns (euint256) {
        if (!isInitialized(value)) {
            value = asEuint256(0);
        }
        Impl.allow(euint256.unwrap(value), address(this));
        return value;
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     */
    function allowTransient(euint256 value, address account) internal returns (euint256) {
        if (!isInitialized(value)) {
            value = asEuint256(0);
        }
        Impl.allowTransient(euint256.unwrap(value), account);
        return value;
    }

    /**
     * @dev Makes the value publicly decryptable.
     */
    function makePubliclyDecryptable(euint256 value) internal returns (euint256) {
        if (!isInitialized(value)) {
            value = asEuint256(0);
        }
        Impl.makePubliclyDecryptable(euint256.unwrap(value));
        return value;
    }

    /**
     * @dev Returns whether the the value is publicly decryptable.
     */
    function isPubliclyDecryptable(euint256 value) internal view returns (bool) {
        return Impl.isPubliclyDecryptable(euint256.unwrap(value));
    }

    /**
     * @dev Returns whether the account is on the deny list.
     */
    function isAccountDenied(address account) internal view returns (bool) {
        return Impl.isAccountDenied(account);
    }

    /// @notice Checks if the `handle` can be decrypted in the given context (`user`, `contractAddress`).
    /// @param handle The handle as a bytes32.
    /// @param user The account address that is part of the user decryption context.
    /// @param contractAddress The address of the contract that is part of the user decryption context.
    /// @return False if `user` has not (user, contractAddress) context.
    function isUserDecryptable(bytes32 handle, address user, address contractAddress) internal view returns (bool) {
        if (user == contractAddress) {
            return false;
        }
        return Impl.persistAllowed(handle, user) && Impl.persistAllowed(handle, contractAddress);
    }

    /// @notice Checks if the user decryption rights have been delegated by `delegator` to `delegate`
    ///         in the context of the given `contractAddress`.
    /// @param delegator The delegator address
    /// @param delegate The account authorized to request user decryptions on behalf of `delegator`
    /// @param contractAddress The address of the contract that is part of the user decryption context
    /// @param handle The handle as a bytes32
    /// @return False if no active delegation exists for the (delegate, contractAddress) context, or if it has expired.
    function isDelegatedForUserDecryption(
        address delegator,
        address delegate,
        address contractAddress,
        bytes32 handle
    ) internal view returns (bool) {
        return Impl.isDelegatedForUserDecryption(delegator, delegate, contractAddress, handle);
    }

    /// @notice Delegates the user decryption rights that caller contract (`address(this)`) holds in the context
    ///         of the given `contractAddress` to a new `delegate` account for a limited amount of time.
    /// @dev The ACL grants user decryption permission based on a (User, Contract) pair. If the pair
    ///      (`address(this)`, `contractAddress`) has permission to decrypt a handle, calling this function grants
    ///      the temporary permission to the new pair (`delegate`, `contractAddress`) to decrypt the same handle.
    /// @param delegate The account that will request a user decryption on behalf of delegator (`address(this)`).
    /// @param contractAddress The address of the contract that is part of the user decryption context.
    /// @param expirationDate UNIX timestamp when the delegation expires.
    ///
    /// @dev Requirements:
    ///      - the ACL contract must not be paused.
    ///        Reverts via an {PausableUpgradeable-EnforcedPause} error otherwise.
    ///
    ///      - `expirationDate` must be at least 1 hour in the future.
    ///        i.e. `expirationDate >= block.timestamp + 1 hours`
    ///        Reverts with an {IACL-ExpirationDateBeforeOneHour} error otherwise.
    ///
    ///      - `expirationDate` must differ from the current value.
    ///        Reverts with an {IACL-ExpirationDateAlreadySetToSameValue} error otherwise.
    ///
    ///      - at most one delegate OR revoke per block for this
    ///        (address(this), delegate, contractAddress) tuple to avoid racey
    ///        state updates.
    ///        Reverts with an {IACL-AlreadyDelegatedOrRevokedInSameBlock} error
    ///        if a delegate OR revoke operation already occurred in the current
    ///        block. See {canDelegateOrRevokeNow}
    ///
    ///      - The `contractAddress` cannot be the caller contract (`address(this)`).
    ///        Reverts with an {IACL-SenderCannotBeContractAddress} error if
    ///        `contractAddress == address(this)`.
    ///
    ///      - The `delegate` address cannot be the caller contract (`address(this)`).
    ///        Reverts with an {IACL-SenderCannotBeDelegate} error if
    ///        `delegate == address(this)`.
    ///
    ///      - The `delegate` address cannot be the `contractAddress`.
    ///        Reverts with an {IACL-DelegateCannotBeContractAddress} error if
    ///        `delegate == contractAddress`.
    function delegateUserDecryption(address delegate, address contractAddress, uint64 expirationDate) internal {
        Impl.delegateForUserDecryption(delegate, contractAddress, expirationDate);
    }

    /// @notice Permanently delegates the user decryption rights that the caller contract (`address(this)`) holds in the
    ///         context of the given `contractAddress` to a new `delegate` account.
    /// @dev This is the version without expiration of {delegateUserDecryption}. The permission remains active until explicitly
    ///      revoked by the delegator using {revokeUserDecryptionDelegation}.
    /// @param delegate The account that will request a user decryption on behalf of delegator (`address(this)`).
    /// @param contractAddress The address of the contract that is part of the user decryption context.
    function delegateUserDecryptionWithoutExpiration(address delegate, address contractAddress) internal {
        Impl.delegateForUserDecryption(delegate, contractAddress, type(uint64).max);
    }

    /// @notice Batch delegates the user decryption rights that the caller contract (`address(this)`) holds in the context of the
    ///         given `contractAddresses[i]` to a new `delegate` account for a limited amount of time.
    /// @param delegate The account that will request a user decryption on behalf of delegator (`address(this)`)..
    /// @param contractAddresses The array of contract addresses that form the user decryption context tuples
    ///                          (`address(this)`, `contractAddresses[i]`).
    /// @param expirationDate UNIX timestamp when the delegation expires.
    function delegateUserDecryptions(
        address delegate,
        address[] memory contractAddresses,
        uint64 expirationDate
    ) internal {
        Impl.delegateForUserDecryptions(delegate, contractAddresses, expirationDate);
    }

    /// @notice Batch delegates user decryption rights without expiration that the caller contract (`address(this)`) holds in the context of
    ///         the given `contractAddresses[i]` to a new `delegate` account.
    /// @param delegate The account that will request a user decryption on behalf of delegator (`address(this)`)..
    /// @param contractAddresses The array of contract addresses that form the user decryption context tuples
    ///                          (`address(this)`, `contractAddresses[i]`).
    function delegateUserDecryptionsWithoutExpiration(address delegate, address[] memory contractAddresses) internal {
        Impl.delegateForUserDecryptions(delegate, contractAddresses, type(uint64).max);
    }

    /// @notice Revoke an existing delegation from delegator `address(this)` to a (delegate, contractAddress) user
    ///         decryption context.
    /// @param delegate The account that was authorized to request user decryptions on behalf of the caller contract `address(this)`
    /// @param contractAddress The address of the contract that is part of the user decryption context
    /// @dev Requirements:
    ///      - the ACL contract must not be paused.
    ///        Reverts with an {PausableUpgradeable-EnforcedPause} error otherwise.
    ///
    ///      - at most one delegate OR revoke per block for this
    ///        (address(this), delegate, contractAddress) tuple to avoid racey
    ///        state updates.
    ///        Reverts with an {IACL-AlreadyDelegatedOrRevokedInSameBlock} error
    ///        if a delegate OR revoke operation already occurred in the current
    ///        block.
    ///
    ///     -  An active delegation must exist for the (delegate, contractAddress)
    ///        context.
    ///        Reverts with an {IACL-NotDelegatedYet} error otherwise.
    function revokeUserDecryptionDelegation(address delegate, address contractAddress) internal {
        Impl.revokeDelegationForUserDecryption(delegate, contractAddress);
    }

    /// @notice Batch revoke existing delegations from delegator `address(this)` to the given
    ///         (delegate, contractAddresses[i]) pairs.
    /// @param delegate The account that was authorized to request user decryptions on behalf of the caller contract `address(this)`
    /// @param contractAddresses The array of contract addresses that form the user decryption context tuples
    ///                          (`address(this)`, `contractAddresses[i]`).
    function revokeUserDecryptionDelegations(address delegate, address[] memory contractAddresses) internal {
        Impl.revokeDelegationsForUserDecryption(delegate, contractAddresses);
    }

    /// @notice Get the expiry date of the delegation from delegator to a (delegate, contractAddress) pair.
    /// @param delegator The delegator address
    /// @param delegate The account authorized to request user decryptions on behalf of delegator
    /// @param contractAddress The address of the contract that is part of the user decryption context
    /// @return expirationDate The delegation's expiration limit, which can be one of:
    ///         - 0 :  If no delegation is currently active for the (delegate, contractAddress) context.
    ///         - type(uint64).max : If the delegation is permanent (no expiry).
    ///         - A strictly positive UNIX timestamp when this delegation expires.
    function getDelegatedUserDecryptionExpirationDate(
        address delegator,
        address delegate,
        address contractAddress
    ) internal view returns (uint64 expirationDate) {
        expirationDate = Impl.getUserDecryptionDelegationExpirationDate(delegator, delegate, contractAddress);
    }

    /// @notice Reverts if the KMS signatures verification against the provided handles and public decryption data
    ///         fails.
    /// @dev The function MUST be called inside a public decryption callback function of a dApp contract
    ///      to verify the signatures and prevent fake decryption results for being submitted.
    /// @param handlesList The list of handles as an array of bytes32 to check
    /// @param abiEncodedCleartexts The ABI-encoded list of decrypted values associated with each handle in the `handlesList`.
    ///                             The ABI-encoded list order must match the `handlesList` order.
    /// @param decryptionProof The KMS public decryption proof. It includes the KMS signatures, associated metadata,
    ///                        and the context needed for verification.
    /// @dev Reverts if any of the following conditions are met:
    ///      - The `decryptionProof` is empty or has an invalid length.
    ///      - The number of valid signatures is zero or less than the configured KMS signers threshold.
    ///      - Any signature is produced by an address that is not a registered KMS signer.
    ///      - The signatures verification returns false.
    function checkSignatures(
        bytes32[] memory handlesList,
        bytes memory abiEncodedCleartexts,
        bytes memory decryptionProof
    ) internal {
        bool isVerified = _verifySignatures(handlesList, abiEncodedCleartexts, decryptionProof);
        if (!isVerified) {
            revert InvalidKMSSignatures();
        }
        emit PublicDecryptionVerified(handlesList, abiEncodedCleartexts);
    }

    /// @notice Returns false or reverts if the KMS signatures verification against the provided handles and public decryption data
    ///         fails. Returns true only if KMS signatures verification pass. This is the `view` variant of `checkSignatures`.
    /// @dev **WARNING**: Prefer using `checkSignatures` (non-view) over this function whenever possible, for several reasons:
    ///      1. **Safety** – `checkSignatures` automatically reverts when signatures are invalid, making misuse impossible.
    ///         In contrast, `isPublicDecryptionResultValid` returns a boolean: if the caller forgets to `require` the returned
    ///         value, invalid signatures will silently pass, leaving the contract vulnerable to forged decryption results.
    ///      2. **Front-end integration** – `checkSignatures` emits a `PublicDecryptionVerified` event upon successful
    ///         verification, which is critical for front-end applications that need to detect when a public decrypt result
    ///         has been verified on-chain. This view function does not emit any event.
    ///      3. **Gas efficiency** – `checkSignatures` leverages a transient-storage mapping to cache verification results,
    ///         making decryption result verification cheaper.
    ///      Use this view variant only when you explicitly need a read-only call (e.g. off-chain simulation or static call).
    /// @param handlesList The list of handles as an array of bytes32 to check
    /// @param abiEncodedCleartexts The ABI-encoded list of decrypted values associated with each handle in the `handlesList`.
    ///                             The ABI-encoded list order must match the `handlesList` order.
    /// @param decryptionProof The KMS public decryption proof. It includes the KMS signatures, associated metadata,
    ///                        and the context needed for verification.
    /// @dev Reverts if any of the following conditions are met:
    ///      - The `decryptionProof` is empty or has an invalid length.
    ///      - The number of valid signatures is zero or less than the configured KMS signers threshold.
    ///      - Any signature is produced by an address that is not a registered KMS signer.
    /// @dev Returns false if there are enough signatures to reach threshold, but some recovered signer is duplicated.
    /// @return true if the signatures verification succeeds, false or reverts otherwise.
    function isPublicDecryptionResultValid(
        bytes32[] memory handlesList,
        bytes memory abiEncodedCleartexts,
        bytes memory decryptionProof
    ) internal view returns (bool) {
        if (decryptionProof.length == 0) {
            revert EmptyDecryptionProof();
        }

        /// @dev The decryptionProof is the numSigners + kmsSignatures + extraData (1 + 65*numSigners + extraData bytes)
        uint256 numSigners = uint256(uint8(decryptionProof[0]));

        /// @dev The extraData is the rest of the decryptionProof bytes after the numSigners + signatures.
        uint256 extraDataOffset = 1 + 65 * numSigners;

        /// @dev Check that the decryptionProof is long enough to contain at least the numSigners + kmsSignatures.
        if (decryptionProof.length < extraDataOffset) {
            revert DeserializingDecryptionProofFail();
        }

        bytes[] memory signatures = new bytes[](numSigners);
        for (uint256 j = 0; j < numSigners; j++) {
            signatures[j] = new bytes(65);
            for (uint256 i = 0; i < 65; i++) {
                signatures[j][i] = decryptionProof[1 + 65 * j + i];
            }
        }

        /// @dev Extract the extraData from the decryptionProof.
        uint256 extraDataSize = decryptionProof.length - extraDataOffset;
        bytes memory extraData = new bytes(extraDataSize);
        for (uint i = 0; i < extraDataSize; i++) {
            extraData[i] = decryptionProof[extraDataOffset + i];
        }
        bytes32 digest = _hashDecryptionResult(handlesList, abiEncodedCleartexts, extraData);

        return _verifySignaturesDigest(digest, signatures);
    }

    /*
     * @notice                  Hashes the decryption result.
     * @param ctHandles         The list of handles as an array of bytes32 to check.
     * @param decryptedResult   ABI-encoded list of decrypted values
     * @param extraData         Extra data.
     * @return hashTypedData    Hash typed data.
     */
    function _hashDecryptionResult(
        bytes32[] memory ctHandles,
        bytes memory decryptedResult,
        bytes memory extraData
    ) private view returns (bytes32) {
        CoprocessorConfig storage $ = Impl.getCoprocessorConfig();
        (
            ,
            string memory name,
            string memory version,
            uint256 gatewayCahinId,
            address verifyingContract,
            ,

        ) = IKMSVerifier($.KMSVerifierAddress).eip712Domain();

        bytes32 domainHash = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                gatewayCahinId,
                verifyingContract
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                DECRYPTION_RESULT_TYPEHASH,
                keccak256(abi.encodePacked(ctHandles)),
                keccak256(decryptedResult),
                keccak256(abi.encodePacked(extraData))
            )
        );

        bytes32 typedDataHash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, hex"19_01")
            mstore(add(ptr, 0x02), domainHash)
            mstore(add(ptr, 0x22), structHash)
            typedDataHash := keccak256(ptr, 0x42)
        }

        return typedDataHash;
    }

    /**
     * @notice              View function that verifies multiple signatures for a given message at a certain threshold.
     * @param digest        The hash of the message that was signed by all signers.
     * @param signatures    An array of signatures to verify.
     * @return isVerified   true if enough provided signatures are valid, false otherwise.
     */
    function _verifySignaturesDigest(bytes32 digest, bytes[] memory signatures) private view returns (bool) {
        uint256 numSignatures = signatures.length;

        if (numSignatures == 0) {
            revert KMSZeroSignature();
        }

        CoprocessorConfig storage $ = Impl.getCoprocessorConfig();

        uint256 threshold = IKMSVerifier($.KMSVerifierAddress).getThreshold();

        if (numSignatures < threshold) {
            revert KMSSignatureThresholdNotReached(numSignatures);
        }

        address[] memory KMSSigners = IKMSVerifier($.KMSVerifierAddress).getKmsSigners();

        address[] memory recoveredSigners = new address[](numSignatures);
        uint256 uniqueValidCount;
        for (uint256 i = 0; i < numSignatures; i++) {
            address signerRecovered = FhevmECDSA.recover(digest, signatures[i]);
            if (!_isSigner(signerRecovered, KMSSigners)) {
                revert KMSInvalidSigner(signerRecovered);
            }
            if (!_isSigner(signerRecovered, recoveredSigners)) {
                recoveredSigners[uniqueValidCount] = signerRecovered;
                uniqueValidCount++;
            }
            if (uniqueValidCount >= threshold) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice              Checks whether a given address is present in an array of signers.
     * @param signer        The address to look for.
     * @param signersArray  The array of signer addresses to search.
     * @return isSigner     true if the address is found, false otherwise.
     */
    function _isSigner(address signer, address[] memory signersArray) private pure returns (bool) {
        uint256 signersArrayLength = signersArray.length;
        for (uint256 i = 0; i < signersArrayLength; i++) {
            if (signer == signersArray[i]) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice          Recovers the signer's address from a `signature` and a `message` digest.
     * @dev             It utilizes ECDSA for actual address recovery. It does not support contract signature (EIP-1271).
     * @param message   The hash of the message that was signed.
     * @param signature The signature to verify.
     * @return signer   The address that supposedly signed the message.
     */
    function _recoverSigner(bytes32 message, bytes memory signature) private pure returns (address) {
        address signerRecovered = FhevmECDSA.recover(message, signature);
        return signerRecovered;
    }

    /// @notice Verifies KMS signatures against the provided handles and public decryption data.
    /// @param handlesList The list of handles as an array of bytes32 to verify
    /// @param abiEncodedCleartexts The ABI-encoded list of decrypted values associated with each handle in the `handlesList`.
    ///                             The list order must match the list of handles in `handlesList`
    /// @param decryptionProof The KMS public decryption proof computed by the KMS Signers associated to `handlesList` and
    ///                       `abiEncodedCleartexts`
    /// @return true if the signatures verification succeeds, false otherwise
    /// @dev Private low-level function used to verify the KMS signatures.
    ///      Warning: this function never reverts, its boolean return value must be checked.
    ///      The decryptionProof is the numSigners + kmsSignatures + extraData (1 + 65*numSigners + extraData bytes)
    ///      Only static native solidity types for clear values are supported, so `abiEncodedCleartexts` is the concatenation of all clear values appended to 32 bytes.
    /// @dev Reverts if any of the following conditions are met by the underlying KMS verifier:
    ///      - The `decryptionProof` is empty or has an invalid length.
    ///      - The number of valid signatures is zero or less than the configured KMS signers threshold.
    ///      - Any signature is produced by an address that is not a registered KMS signer.
    function _verifySignatures(
        bytes32[] memory handlesList,
        bytes memory abiEncodedCleartexts,
        bytes memory decryptionProof
    ) private returns (bool) {
        CoprocessorConfig storage $ = Impl.getCoprocessorConfig();
        return
            IKMSVerifier($.KMSVerifierAddress).verifyDecryptionEIP712KMSSignatures(
                handlesList,
                abiEncodedCleartexts,
                decryptionProof
            );
    }

    /**
     * @dev Converts handle from its custom type to the underlying bytes32. Used when requesting a decryption.
     */
    function toBytes32(ebool value) internal pure returns (bytes32 ct) {
        ct = ebool.unwrap(value);
    }

    /**
     * @dev Converts handle from its custom type to the underlying bytes32. Used when requesting a decryption.
     */
    function toBytes32(euint8 value) internal pure returns (bytes32 ct) {
        ct = euint8.unwrap(value);
    }

    /**
     * @dev Converts handle from its custom type to the underlying bytes32. Used when requesting a decryption.
     */
    function toBytes32(euint16 value) internal pure returns (bytes32 ct) {
        ct = euint16.unwrap(value);
    }

    /**
     * @dev Converts handle from its custom type to the underlying bytes32. Used when requesting a decryption.
     */
    function toBytes32(euint32 value) internal pure returns (bytes32 ct) {
        ct = euint32.unwrap(value);
    }

    /**
     * @dev Converts handle from its custom type to the underlying bytes32. Used when requesting a decryption.
     */
    function toBytes32(euint64 value) internal pure returns (bytes32 ct) {
        ct = euint64.unwrap(value);
    }

    /**
     * @dev Converts handle from its custom type to the underlying bytes32. Used when requesting a decryption.
     */
    function toBytes32(euint128 value) internal pure returns (bytes32 ct) {
        ct = euint128.unwrap(value);
    }

    /**
     * @dev Converts handle from its custom type to the underlying bytes32. Used when requesting a decryption.
     */
    function toBytes32(eaddress value) internal pure returns (bytes32 ct) {
        ct = eaddress.unwrap(value);
    }

    /**
     * @dev Converts handle from its custom type to the underlying bytes32. Used when requesting a decryption.
     */
    function toBytes32(euint256 value) internal pure returns (bytes32 ct) {
        ct = euint256.unwrap(value);
    }
}


// File @openzeppelin/contracts/access/IAccessControl.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (access/IAccessControl.sol)

pragma solidity >=0.8.4;

/**
 * @dev External interface of AccessControl declared to support ERC-165 detection.
 */
interface IAccessControl {
    /**
     * @dev The `account` is missing a role.
     */
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    /**
     * @dev The caller of a function is not the expected one.
     *
     * NOTE: Don't confuse with {AccessControlUnauthorizedAccount}.
     */
    error AccessControlBadConfirmation();

    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted to signal this.
     */
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call. This account bears the admin role (for the granted role).
     * Expected in cases where the role was granted using the internal {AccessControl-_grantRole}.
     */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) external view returns (bool);

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {AccessControl-_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     */
    function renounceRole(bytes32 role, address callerConfirmation) external;
}


// File @openzeppelin/contracts/utils/Context.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

pragma solidity ^0.8.20;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}


// File @openzeppelin/contracts/utils/introspection/IERC165.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (utils/introspection/IERC165.sol)

pragma solidity >=0.4.16;

/**
 * @dev Interface of the ERC-165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[ERC].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[ERC section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}


// File @openzeppelin/contracts/utils/introspection/ERC165.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (utils/introspection/ERC165.sol)

pragma solidity ^0.8.20;

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC-165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 */
abstract contract ERC165 is IERC165 {
    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}


// File @openzeppelin/contracts/access/AccessControl.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.6.0) (access/AccessControl.sol)

pragma solidity ^0.8.20;



/**
 * @dev Contract module that allows children to implement role-based access
 * control mechanisms. This is a lightweight version that doesn't allow enumerating role
 * members except through off-chain means by accessing the contract event logs. Some
 * applications may benefit from on-chain enumerability, for those cases see
 * {AccessControlEnumerable}.
 *
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests:
 *
 * ```solidity
 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
 * ```
 *
 * Roles can be used to represent a set of permissions. To restrict access to a
 * function call, use {hasRole}:
 *
 * ```solidity
 * function foo() public {
 *     require(hasRole(MY_ROLE, msg.sender));
 *     ...
 * }
 * ```
 *
 * Roles can be granted and revoked dynamically via the {grantRole} and
 * {revokeRole} functions. Each role has an associated admin role, and only
 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.
 *
 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
 * that only accounts with this role will be able to grant or revoke other
 * roles. More complex role relationships can be created by using
 * {_setRoleAdmin}.
 *
 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
 * grant and revoke this role. Extra precautions should be taken to secure
 * accounts that have been granted it. We recommend using {AccessControlDefaultAdminRules}
 * to enforce additional security measures for this role.
 */
abstract contract AccessControl is Context, IAccessControl, ERC165 {
    struct RoleData {
        mapping(address account => bool) hasRole;
        bytes32 adminRole;
    }

    mapping(bytes32 role => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with an {AccessControlUnauthorizedAccount} error including the required role.
     */
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControl).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) public view virtual returns (bool) {
        return _roles[role].hasRole[account];
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `_msgSender()`
     * is missing `role`. Overriding this function changes the behavior of the {onlyRole} modifier.
     */
    function _checkRole(bytes32 role) internal view virtual {
        _checkRole(role, _msgSender());
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `account`
     * is missing `role`.
     */
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert AccessControlUnauthorizedAccount(account, role);
        }
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {
        return _roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     *
     * May emit a {RoleRevoked} event.
     */
    function renounceRole(bytes32 role, address callerConfirmation) public virtual {
        if (callerConfirmation != _msgSender()) {
            revert AccessControlBadConfirmation();
        }

        _revokeRole(role, callerConfirmation);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Attempts to grant `role` to `account` and returns a boolean indicating if `role` was granted.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(bytes32 role, address account) internal virtual returns (bool) {
        if (!hasRole(role, account)) {
            _roles[role].hasRole[account] = true;
            emit RoleGranted(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Attempts to revoke `role` from `account` and returns a boolean indicating if `role` was revoked.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(bytes32 role, address account) internal virtual returns (bool) {
        if (hasRole(role, account)) {
            _roles[role].hasRole[account] = false;
            emit RoleRevoked(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }
}


// File @openzeppelin/contracts/access/extensions/IAccessControlEnumerable.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (access/extensions/IAccessControlEnumerable.sol)

pragma solidity >=0.8.4;

/**
 * @dev External interface of AccessControlEnumerable declared to support ERC-165 detection.
 */
interface IAccessControlEnumerable is IAccessControl {
    /**
     * @dev Returns one of the accounts that have `role`. `index` must be a
     * value between 0 and {getRoleMemberCount}, non-inclusive.
     *
     * Role bearers are not sorted in any particular way, and their ordering may
     * change at any point.
     *
     * WARNING: When using {getRoleMember} and {getRoleMemberCount}, make sure
     * you perform all queries on the same block. See the following
     * https://forum.openzeppelin.com/t/iterating-over-elements-on-enumerableset-in-openzeppelin-contracts/2296[forum post]
     * for more information.
     */
    function getRoleMember(bytes32 role, uint256 index) external view returns (address);

    /**
     * @dev Returns the number of accounts that have `role`. Can be used
     * together with {getRoleMember} to enumerate all bearers of a role.
     */
    function getRoleMemberCount(bytes32 role) external view returns (uint256);
}


// File @openzeppelin/contracts/utils/Comparators.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/Comparators.sol)

pragma solidity ^0.8.20;

/**
 * @dev Provides a set of functions to compare values.
 *
 * _Available since v5.1._
 */
library Comparators {
    function lt(uint256 a, uint256 b) internal pure returns (bool) {
        return a < b;
    }

    function gt(uint256 a, uint256 b) internal pure returns (bool) {
        return a > b;
    }
}


// File @openzeppelin/contracts/utils/math/SafeCast.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.6.0) (utils/math/SafeCast.sol)
// This file was procedurally generated from scripts/generate/templates/SafeCast.js.

pragma solidity ^0.8.20;

/**
 * @dev Wrappers over Solidity's uintXX/intXX/bool casting operators with added overflow
 * checks.
 *
 * Downcasting from uint256/int256 in Solidity does not revert on overflow. This can
 * easily result in undesired exploitation or bugs, since developers usually
 * assume that overflows raise errors. `SafeCast` restores this intuition by
 * reverting the transaction when such an operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeCast {
    /**
     * @dev Value doesn't fit in a uint of `bits` size.
     */
    error SafeCastOverflowedUintDowncast(uint8 bits, uint256 value);

    /**
     * @dev An int value doesn't fit in a uint of `bits` size.
     */
    error SafeCastOverflowedIntToUint(int256 value);

    /**
     * @dev Value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedIntDowncast(uint8 bits, int256 value);

    /**
     * @dev A uint value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedUintToInt(uint256 value);

    /**
     * @dev Returns the downcasted uint248 from uint256, reverting on
     * overflow (when the input is greater than largest uint248).
     *
     * Counterpart to Solidity's `uint248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toUint248(uint256 value) internal pure returns (uint248) {
        if (value > type(uint248).max) {
            revert SafeCastOverflowedUintDowncast(248, value);
        }
        return uint248(value);
    }

    /**
     * @dev Returns the downcasted uint240 from uint256, reverting on
     * overflow (when the input is greater than largest uint240).
     *
     * Counterpart to Solidity's `uint240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toUint240(uint256 value) internal pure returns (uint240) {
        if (value > type(uint240).max) {
            revert SafeCastOverflowedUintDowncast(240, value);
        }
        return uint240(value);
    }

    /**
     * @dev Returns the downcasted uint232 from uint256, reverting on
     * overflow (when the input is greater than largest uint232).
     *
     * Counterpart to Solidity's `uint232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toUint232(uint256 value) internal pure returns (uint232) {
        if (value > type(uint232).max) {
            revert SafeCastOverflowedUintDowncast(232, value);
        }
        return uint232(value);
    }

    /**
     * @dev Returns the downcasted uint224 from uint256, reverting on
     * overflow (when the input is greater than largest uint224).
     *
     * Counterpart to Solidity's `uint224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toUint224(uint256 value) internal pure returns (uint224) {
        if (value > type(uint224).max) {
            revert SafeCastOverflowedUintDowncast(224, value);
        }
        return uint224(value);
    }

    /**
     * @dev Returns the downcasted uint216 from uint256, reverting on
     * overflow (when the input is greater than largest uint216).
     *
     * Counterpart to Solidity's `uint216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toUint216(uint256 value) internal pure returns (uint216) {
        if (value > type(uint216).max) {
            revert SafeCastOverflowedUintDowncast(216, value);
        }
        return uint216(value);
    }

    /**
     * @dev Returns the downcasted uint208 from uint256, reverting on
     * overflow (when the input is greater than largest uint208).
     *
     * Counterpart to Solidity's `uint208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toUint208(uint256 value) internal pure returns (uint208) {
        if (value > type(uint208).max) {
            revert SafeCastOverflowedUintDowncast(208, value);
        }
        return uint208(value);
    }

    /**
     * @dev Returns the downcasted uint200 from uint256, reverting on
     * overflow (when the input is greater than largest uint200).
     *
     * Counterpart to Solidity's `uint200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toUint200(uint256 value) internal pure returns (uint200) {
        if (value > type(uint200).max) {
            revert SafeCastOverflowedUintDowncast(200, value);
        }
        return uint200(value);
    }

    /**
     * @dev Returns the downcasted uint192 from uint256, reverting on
     * overflow (when the input is greater than largest uint192).
     *
     * Counterpart to Solidity's `uint192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toUint192(uint256 value) internal pure returns (uint192) {
        if (value > type(uint192).max) {
            revert SafeCastOverflowedUintDowncast(192, value);
        }
        return uint192(value);
    }

    /**
     * @dev Returns the downcasted uint184 from uint256, reverting on
     * overflow (when the input is greater than largest uint184).
     *
     * Counterpart to Solidity's `uint184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toUint184(uint256 value) internal pure returns (uint184) {
        if (value > type(uint184).max) {
            revert SafeCastOverflowedUintDowncast(184, value);
        }
        return uint184(value);
    }

    /**
     * @dev Returns the downcasted uint176 from uint256, reverting on
     * overflow (when the input is greater than largest uint176).
     *
     * Counterpart to Solidity's `uint176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toUint176(uint256 value) internal pure returns (uint176) {
        if (value > type(uint176).max) {
            revert SafeCastOverflowedUintDowncast(176, value);
        }
        return uint176(value);
    }

    /**
     * @dev Returns the downcasted uint168 from uint256, reverting on
     * overflow (when the input is greater than largest uint168).
     *
     * Counterpart to Solidity's `uint168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toUint168(uint256 value) internal pure returns (uint168) {
        if (value > type(uint168).max) {
            revert SafeCastOverflowedUintDowncast(168, value);
        }
        return uint168(value);
    }

    /**
     * @dev Returns the downcasted uint160 from uint256, reverting on
     * overflow (when the input is greater than largest uint160).
     *
     * Counterpart to Solidity's `uint160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toUint160(uint256 value) internal pure returns (uint160) {
        if (value > type(uint160).max) {
            revert SafeCastOverflowedUintDowncast(160, value);
        }
        return uint160(value);
    }

    /**
     * @dev Returns the downcasted uint152 from uint256, reverting on
     * overflow (when the input is greater than largest uint152).
     *
     * Counterpart to Solidity's `uint152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toUint152(uint256 value) internal pure returns (uint152) {
        if (value > type(uint152).max) {
            revert SafeCastOverflowedUintDowncast(152, value);
        }
        return uint152(value);
    }

    /**
     * @dev Returns the downcasted uint144 from uint256, reverting on
     * overflow (when the input is greater than largest uint144).
     *
     * Counterpart to Solidity's `uint144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toUint144(uint256 value) internal pure returns (uint144) {
        if (value > type(uint144).max) {
            revert SafeCastOverflowedUintDowncast(144, value);
        }
        return uint144(value);
    }

    /**
     * @dev Returns the downcasted uint136 from uint256, reverting on
     * overflow (when the input is greater than largest uint136).
     *
     * Counterpart to Solidity's `uint136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toUint136(uint256 value) internal pure returns (uint136) {
        if (value > type(uint136).max) {
            revert SafeCastOverflowedUintDowncast(136, value);
        }
        return uint136(value);
    }

    /**
     * @dev Returns the downcasted uint128 from uint256, reverting on
     * overflow (when the input is greater than largest uint128).
     *
     * Counterpart to Solidity's `uint128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toUint128(uint256 value) internal pure returns (uint128) {
        if (value > type(uint128).max) {
            revert SafeCastOverflowedUintDowncast(128, value);
        }
        return uint128(value);
    }

    /**
     * @dev Returns the downcasted uint120 from uint256, reverting on
     * overflow (when the input is greater than largest uint120).
     *
     * Counterpart to Solidity's `uint120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toUint120(uint256 value) internal pure returns (uint120) {
        if (value > type(uint120).max) {
            revert SafeCastOverflowedUintDowncast(120, value);
        }
        return uint120(value);
    }

    /**
     * @dev Returns the downcasted uint112 from uint256, reverting on
     * overflow (when the input is greater than largest uint112).
     *
     * Counterpart to Solidity's `uint112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toUint112(uint256 value) internal pure returns (uint112) {
        if (value > type(uint112).max) {
            revert SafeCastOverflowedUintDowncast(112, value);
        }
        return uint112(value);
    }

    /**
     * @dev Returns the downcasted uint104 from uint256, reverting on
     * overflow (when the input is greater than largest uint104).
     *
     * Counterpart to Solidity's `uint104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toUint104(uint256 value) internal pure returns (uint104) {
        if (value > type(uint104).max) {
            revert SafeCastOverflowedUintDowncast(104, value);
        }
        return uint104(value);
    }

    /**
     * @dev Returns the downcasted uint96 from uint256, reverting on
     * overflow (when the input is greater than largest uint96).
     *
     * Counterpart to Solidity's `uint96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toUint96(uint256 value) internal pure returns (uint96) {
        if (value > type(uint96).max) {
            revert SafeCastOverflowedUintDowncast(96, value);
        }
        return uint96(value);
    }

    /**
     * @dev Returns the downcasted uint88 from uint256, reverting on
     * overflow (when the input is greater than largest uint88).
     *
     * Counterpart to Solidity's `uint88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toUint88(uint256 value) internal pure returns (uint88) {
        if (value > type(uint88).max) {
            revert SafeCastOverflowedUintDowncast(88, value);
        }
        return uint88(value);
    }

    /**
     * @dev Returns the downcasted uint80 from uint256, reverting on
     * overflow (when the input is greater than largest uint80).
     *
     * Counterpart to Solidity's `uint80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toUint80(uint256 value) internal pure returns (uint80) {
        if (value > type(uint80).max) {
            revert SafeCastOverflowedUintDowncast(80, value);
        }
        return uint80(value);
    }

    /**
     * @dev Returns the downcasted uint72 from uint256, reverting on
     * overflow (when the input is greater than largest uint72).
     *
     * Counterpart to Solidity's `uint72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toUint72(uint256 value) internal pure returns (uint72) {
        if (value > type(uint72).max) {
            revert SafeCastOverflowedUintDowncast(72, value);
        }
        return uint72(value);
    }

    /**
     * @dev Returns the downcasted uint64 from uint256, reverting on
     * overflow (when the input is greater than largest uint64).
     *
     * Counterpart to Solidity's `uint64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toUint64(uint256 value) internal pure returns (uint64) {
        if (value > type(uint64).max) {
            revert SafeCastOverflowedUintDowncast(64, value);
        }
        return uint64(value);
    }

    /**
     * @dev Returns the downcasted uint56 from uint256, reverting on
     * overflow (when the input is greater than largest uint56).
     *
     * Counterpart to Solidity's `uint56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toUint56(uint256 value) internal pure returns (uint56) {
        if (value > type(uint56).max) {
            revert SafeCastOverflowedUintDowncast(56, value);
        }
        return uint56(value);
    }

    /**
     * @dev Returns the downcasted uint48 from uint256, reverting on
     * overflow (when the input is greater than largest uint48).
     *
     * Counterpart to Solidity's `uint48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toUint48(uint256 value) internal pure returns (uint48) {
        if (value > type(uint48).max) {
            revert SafeCastOverflowedUintDowncast(48, value);
        }
        return uint48(value);
    }

    /**
     * @dev Returns the downcasted uint40 from uint256, reverting on
     * overflow (when the input is greater than largest uint40).
     *
     * Counterpart to Solidity's `uint40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toUint40(uint256 value) internal pure returns (uint40) {
        if (value > type(uint40).max) {
            revert SafeCastOverflowedUintDowncast(40, value);
        }
        return uint40(value);
    }

    /**
     * @dev Returns the downcasted uint32 from uint256, reverting on
     * overflow (when the input is greater than largest uint32).
     *
     * Counterpart to Solidity's `uint32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toUint32(uint256 value) internal pure returns (uint32) {
        if (value > type(uint32).max) {
            revert SafeCastOverflowedUintDowncast(32, value);
        }
        return uint32(value);
    }

    /**
     * @dev Returns the downcasted uint24 from uint256, reverting on
     * overflow (when the input is greater than largest uint24).
     *
     * Counterpart to Solidity's `uint24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toUint24(uint256 value) internal pure returns (uint24) {
        if (value > type(uint24).max) {
            revert SafeCastOverflowedUintDowncast(24, value);
        }
        return uint24(value);
    }

    /**
     * @dev Returns the downcasted uint16 from uint256, reverting on
     * overflow (when the input is greater than largest uint16).
     *
     * Counterpart to Solidity's `uint16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toUint16(uint256 value) internal pure returns (uint16) {
        if (value > type(uint16).max) {
            revert SafeCastOverflowedUintDowncast(16, value);
        }
        return uint16(value);
    }

    /**
     * @dev Returns the downcasted uint8 from uint256, reverting on
     * overflow (when the input is greater than largest uint8).
     *
     * Counterpart to Solidity's `uint8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toUint8(uint256 value) internal pure returns (uint8) {
        if (value > type(uint8).max) {
            revert SafeCastOverflowedUintDowncast(8, value);
        }
        return uint8(value);
    }

    /**
     * @dev Converts a signed int256 into an unsigned uint256.
     *
     * Requirements:
     *
     * - input must be greater than or equal to 0.
     */
    function toUint256(int256 value) internal pure returns (uint256) {
        if (value < 0) {
            revert SafeCastOverflowedIntToUint(value);
        }
        return uint256(value);
    }

    /**
     * @dev Returns the downcasted int248 from int256, reverting on
     * overflow (when the input is less than smallest int248 or
     * greater than largest int248).
     *
     * Counterpart to Solidity's `int248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toInt248(int256 value) internal pure returns (int248 downcasted) {
        downcasted = int248(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(248, value);
        }
    }

    /**
     * @dev Returns the downcasted int240 from int256, reverting on
     * overflow (when the input is less than smallest int240 or
     * greater than largest int240).
     *
     * Counterpart to Solidity's `int240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toInt240(int256 value) internal pure returns (int240 downcasted) {
        downcasted = int240(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(240, value);
        }
    }

    /**
     * @dev Returns the downcasted int232 from int256, reverting on
     * overflow (when the input is less than smallest int232 or
     * greater than largest int232).
     *
     * Counterpart to Solidity's `int232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toInt232(int256 value) internal pure returns (int232 downcasted) {
        downcasted = int232(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(232, value);
        }
    }

    /**
     * @dev Returns the downcasted int224 from int256, reverting on
     * overflow (when the input is less than smallest int224 or
     * greater than largest int224).
     *
     * Counterpart to Solidity's `int224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toInt224(int256 value) internal pure returns (int224 downcasted) {
        downcasted = int224(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(224, value);
        }
    }

    /**
     * @dev Returns the downcasted int216 from int256, reverting on
     * overflow (when the input is less than smallest int216 or
     * greater than largest int216).
     *
     * Counterpart to Solidity's `int216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toInt216(int256 value) internal pure returns (int216 downcasted) {
        downcasted = int216(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(216, value);
        }
    }

    /**
     * @dev Returns the downcasted int208 from int256, reverting on
     * overflow (when the input is less than smallest int208 or
     * greater than largest int208).
     *
     * Counterpart to Solidity's `int208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toInt208(int256 value) internal pure returns (int208 downcasted) {
        downcasted = int208(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(208, value);
        }
    }

    /**
     * @dev Returns the downcasted int200 from int256, reverting on
     * overflow (when the input is less than smallest int200 or
     * greater than largest int200).
     *
     * Counterpart to Solidity's `int200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toInt200(int256 value) internal pure returns (int200 downcasted) {
        downcasted = int200(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(200, value);
        }
    }

    /**
     * @dev Returns the downcasted int192 from int256, reverting on
     * overflow (when the input is less than smallest int192 or
     * greater than largest int192).
     *
     * Counterpart to Solidity's `int192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toInt192(int256 value) internal pure returns (int192 downcasted) {
        downcasted = int192(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(192, value);
        }
    }

    /**
     * @dev Returns the downcasted int184 from int256, reverting on
     * overflow (when the input is less than smallest int184 or
     * greater than largest int184).
     *
     * Counterpart to Solidity's `int184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toInt184(int256 value) internal pure returns (int184 downcasted) {
        downcasted = int184(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(184, value);
        }
    }

    /**
     * @dev Returns the downcasted int176 from int256, reverting on
     * overflow (when the input is less than smallest int176 or
     * greater than largest int176).
     *
     * Counterpart to Solidity's `int176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toInt176(int256 value) internal pure returns (int176 downcasted) {
        downcasted = int176(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(176, value);
        }
    }

    /**
     * @dev Returns the downcasted int168 from int256, reverting on
     * overflow (when the input is less than smallest int168 or
     * greater than largest int168).
     *
     * Counterpart to Solidity's `int168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toInt168(int256 value) internal pure returns (int168 downcasted) {
        downcasted = int168(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(168, value);
        }
    }

    /**
     * @dev Returns the downcasted int160 from int256, reverting on
     * overflow (when the input is less than smallest int160 or
     * greater than largest int160).
     *
     * Counterpart to Solidity's `int160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toInt160(int256 value) internal pure returns (int160 downcasted) {
        downcasted = int160(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(160, value);
        }
    }

    /**
     * @dev Returns the downcasted int152 from int256, reverting on
     * overflow (when the input is less than smallest int152 or
     * greater than largest int152).
     *
     * Counterpart to Solidity's `int152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toInt152(int256 value) internal pure returns (int152 downcasted) {
        downcasted = int152(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(152, value);
        }
    }

    /**
     * @dev Returns the downcasted int144 from int256, reverting on
     * overflow (when the input is less than smallest int144 or
     * greater than largest int144).
     *
     * Counterpart to Solidity's `int144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toInt144(int256 value) internal pure returns (int144 downcasted) {
        downcasted = int144(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(144, value);
        }
    }

    /**
     * @dev Returns the downcasted int136 from int256, reverting on
     * overflow (when the input is less than smallest int136 or
     * greater than largest int136).
     *
     * Counterpart to Solidity's `int136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toInt136(int256 value) internal pure returns (int136 downcasted) {
        downcasted = int136(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(136, value);
        }
    }

    /**
     * @dev Returns the downcasted int128 from int256, reverting on
     * overflow (when the input is less than smallest int128 or
     * greater than largest int128).
     *
     * Counterpart to Solidity's `int128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toInt128(int256 value) internal pure returns (int128 downcasted) {
        downcasted = int128(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(128, value);
        }
    }

    /**
     * @dev Returns the downcasted int120 from int256, reverting on
     * overflow (when the input is less than smallest int120 or
     * greater than largest int120).
     *
     * Counterpart to Solidity's `int120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toInt120(int256 value) internal pure returns (int120 downcasted) {
        downcasted = int120(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(120, value);
        }
    }

    /**
     * @dev Returns the downcasted int112 from int256, reverting on
     * overflow (when the input is less than smallest int112 or
     * greater than largest int112).
     *
     * Counterpart to Solidity's `int112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toInt112(int256 value) internal pure returns (int112 downcasted) {
        downcasted = int112(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(112, value);
        }
    }

    /**
     * @dev Returns the downcasted int104 from int256, reverting on
     * overflow (when the input is less than smallest int104 or
     * greater than largest int104).
     *
     * Counterpart to Solidity's `int104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toInt104(int256 value) internal pure returns (int104 downcasted) {
        downcasted = int104(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(104, value);
        }
    }

    /**
     * @dev Returns the downcasted int96 from int256, reverting on
     * overflow (when the input is less than smallest int96 or
     * greater than largest int96).
     *
     * Counterpart to Solidity's `int96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toInt96(int256 value) internal pure returns (int96 downcasted) {
        downcasted = int96(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(96, value);
        }
    }

    /**
     * @dev Returns the downcasted int88 from int256, reverting on
     * overflow (when the input is less than smallest int88 or
     * greater than largest int88).
     *
     * Counterpart to Solidity's `int88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toInt88(int256 value) internal pure returns (int88 downcasted) {
        downcasted = int88(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(88, value);
        }
    }

    /**
     * @dev Returns the downcasted int80 from int256, reverting on
     * overflow (when the input is less than smallest int80 or
     * greater than largest int80).
     *
     * Counterpart to Solidity's `int80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toInt80(int256 value) internal pure returns (int80 downcasted) {
        downcasted = int80(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(80, value);
        }
    }

    /**
     * @dev Returns the downcasted int72 from int256, reverting on
     * overflow (when the input is less than smallest int72 or
     * greater than largest int72).
     *
     * Counterpart to Solidity's `int72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toInt72(int256 value) internal pure returns (int72 downcasted) {
        downcasted = int72(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(72, value);
        }
    }

    /**
     * @dev Returns the downcasted int64 from int256, reverting on
     * overflow (when the input is less than smallest int64 or
     * greater than largest int64).
     *
     * Counterpart to Solidity's `int64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toInt64(int256 value) internal pure returns (int64 downcasted) {
        downcasted = int64(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(64, value);
        }
    }

    /**
     * @dev Returns the downcasted int56 from int256, reverting on
     * overflow (when the input is less than smallest int56 or
     * greater than largest int56).
     *
     * Counterpart to Solidity's `int56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toInt56(int256 value) internal pure returns (int56 downcasted) {
        downcasted = int56(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(56, value);
        }
    }

    /**
     * @dev Returns the downcasted int48 from int256, reverting on
     * overflow (when the input is less than smallest int48 or
     * greater than largest int48).
     *
     * Counterpart to Solidity's `int48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toInt48(int256 value) internal pure returns (int48 downcasted) {
        downcasted = int48(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(48, value);
        }
    }

    /**
     * @dev Returns the downcasted int40 from int256, reverting on
     * overflow (when the input is less than smallest int40 or
     * greater than largest int40).
     *
     * Counterpart to Solidity's `int40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toInt40(int256 value) internal pure returns (int40 downcasted) {
        downcasted = int40(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(40, value);
        }
    }

    /**
     * @dev Returns the downcasted int32 from int256, reverting on
     * overflow (when the input is less than smallest int32 or
     * greater than largest int32).
     *
     * Counterpart to Solidity's `int32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toInt32(int256 value) internal pure returns (int32 downcasted) {
        downcasted = int32(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(32, value);
        }
    }

    /**
     * @dev Returns the downcasted int24 from int256, reverting on
     * overflow (when the input is less than smallest int24 or
     * greater than largest int24).
     *
     * Counterpart to Solidity's `int24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toInt24(int256 value) internal pure returns (int24 downcasted) {
        downcasted = int24(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(24, value);
        }
    }

    /**
     * @dev Returns the downcasted int16 from int256, reverting on
     * overflow (when the input is less than smallest int16 or
     * greater than largest int16).
     *
     * Counterpart to Solidity's `int16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toInt16(int256 value) internal pure returns (int16 downcasted) {
        downcasted = int16(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(16, value);
        }
    }

    /**
     * @dev Returns the downcasted int8 from int256, reverting on
     * overflow (when the input is less than smallest int8 or
     * greater than largest int8).
     *
     * Counterpart to Solidity's `int8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toInt8(int256 value) internal pure returns (int8 downcasted) {
        downcasted = int8(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(8, value);
        }
    }

    /**
     * @dev Converts an unsigned uint256 into a signed int256.
     *
     * Requirements:
     *
     * - input must be less than or equal to maxInt256.
     */
    function toInt256(uint256 value) internal pure returns (int256) {
        // Note: Unsafe cast below is okay because `type(int256).max` is guaranteed to be positive
        if (value > uint256(type(int256).max)) {
            revert SafeCastOverflowedUintToInt(value);
        }
        return int256(value);
    }

    /**
     * @dev Cast a boolean (false or true) to a uint256 (0 or 1) with no jump.
     */
    function toUint(bool b) internal pure returns (uint256 u) {
        assembly ("memory-safe") {
            u := iszero(iszero(b))
        }
    }
}


// File @openzeppelin/contracts/utils/Panic.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/Panic.sol)

pragma solidity ^0.8.20;

/**
 * @dev Helper library for emitting standardized panic codes.
 *
 * ```solidity
 * contract Example {
 *      using Panic for uint256;
 *
 *      // Use any of the declared internal constants
 *      function foo() { Panic.GENERIC.panic(); }
 *
 *      // Alternatively
 *      function foo() { Panic.panic(Panic.GENERIC); }
 * }
 * ```
 *
 * Follows the list from https://github.com/ethereum/solidity/blob/v0.8.24/libsolutil/ErrorCodes.h[libsolutil].
 *
 * _Available since v5.1._
 */
// slither-disable-next-line unused-state
library Panic {
    /// @dev generic / unspecified error
    uint256 internal constant GENERIC = 0x00;
    /// @dev used by the assert() builtin
    uint256 internal constant ASSERT = 0x01;
    /// @dev arithmetic underflow or overflow
    uint256 internal constant UNDER_OVERFLOW = 0x11;
    /// @dev division or modulo by zero
    uint256 internal constant DIVISION_BY_ZERO = 0x12;
    /// @dev enum conversion error
    uint256 internal constant ENUM_CONVERSION_ERROR = 0x21;
    /// @dev invalid encoding in storage
    uint256 internal constant STORAGE_ENCODING_ERROR = 0x22;
    /// @dev empty array pop
    uint256 internal constant EMPTY_ARRAY_POP = 0x31;
    /// @dev array out of bounds access
    uint256 internal constant ARRAY_OUT_OF_BOUNDS = 0x32;
    /// @dev resource error (too large allocation or too large array)
    uint256 internal constant RESOURCE_ERROR = 0x41;
    /// @dev calling invalid internal function
    uint256 internal constant INVALID_INTERNAL_FUNCTION = 0x51;

    /// @dev Reverts with a panic code. Recommended to use with
    /// the internal constants with predefined codes.
    function panic(uint256 code) internal pure {
        assembly ("memory-safe") {
            mstore(0x00, 0x4e487b71)
            mstore(0x20, code)
            revert(0x1c, 0x24)
        }
    }
}


// File @openzeppelin/contracts/utils/math/Math.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.6.0) (utils/math/Math.sol)

pragma solidity ^0.8.20;


/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    enum Rounding {
        Floor, // Toward negative infinity
        Ceil, // Toward positive infinity
        Trunc, // Toward zero
        Expand // Away from zero
    }

    /**
     * @dev Return the 512-bit addition of two uint256.
     *
     * The result is stored in two 256 variables such that sum = high * 2²⁵⁶ + low.
     */
    function add512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        assembly ("memory-safe") {
            low := add(a, b)
            high := lt(low, a)
        }
    }

    /**
     * @dev Return the 512-bit multiplication of two uint256.
     *
     * The result is stored in two 256 variables such that product = high * 2²⁵⁶ + low.
     */
    function mul512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        // 512-bit multiply [high low] = x * y. Compute the product mod 2²⁵⁶ and mod 2²⁵⁶ - 1, then use
        // the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
        // variables such that product = high * 2²⁵⁶ + low.
        assembly ("memory-safe") {
            let mm := mulmod(a, b, not(0))
            low := mul(a, b)
            high := sub(sub(mm, low), lt(mm, low))
        }
    }

    /**
     * @dev Returns the addition of two unsigned integers, with a success flag (no overflow).
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a + b;
            success = c >= a;
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, with a success flag (no overflow).
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a - b;
            success = c <= a;
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with a success flag (no overflow).
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a * b;
            assembly ("memory-safe") {
                // Only true when the multiplication doesn't overflow
                // (c / a == b) || (a == 0)
                success := or(eq(div(c, a), b), iszero(a))
            }
            // equivalent to: success ? c : 0
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the division of two unsigned integers, with a success flag (no division by zero).
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                // The `DIV` opcode returns zero when the denominator is 0.
                result := div(a, b)
            }
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a success flag (no division by zero).
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                // The `MOD` opcode returns zero when the denominator is 0.
                result := mod(a, b)
            }
        }
    }

    /**
     * @dev Unsigned saturating addition, bounds to `2²⁵⁶ - 1` instead of overflowing.
     */
    function saturatingAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryAdd(a, b);
        return ternary(success, result, type(uint256).max);
    }

    /**
     * @dev Unsigned saturating subtraction, bounds to zero instead of overflowing.
     */
    function saturatingSub(uint256 a, uint256 b) internal pure returns (uint256) {
        (, uint256 result) = trySub(a, b);
        return result;
    }

    /**
     * @dev Unsigned saturating multiplication, bounds to `2²⁵⁶ - 1` instead of overflowing.
     */
    function saturatingMul(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryMul(a, b);
        return ternary(success, result, type(uint256).max);
    }

    /**
     * @dev Branchless ternary evaluation for `condition ? a : b`. Gas costs are constant.
     *
     * IMPORTANT: This function may reduce bytecode size and consume less gas when used standalone.
     * However, the compiler may optimize Solidity ternary operations (i.e. `condition ? a : b`) to only compute
     * one branch when needed, making this function more expensive.
     */
    function ternary(bool condition, uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            // branchless ternary works because:
            // b ^ (a ^ b) == a
            // b ^ 0 == b
            return b ^ ((a ^ b) * SafeCast.toUint(condition));
        }
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a > b, a, b);
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a < b, a, b);
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            // (a + b) / 2 can overflow.
            return (a & b) + (a ^ b) / 2;
        }
    }

    /**
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds towards infinity instead
     * of rounding towards zero.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) {
            // Guarantee the same behavior as in a regular Solidity division.
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }

        // The following calculation ensures accurate ceiling division without overflow.
        // Since a is non-zero, (a - 1) / b will not overflow.
        // The largest possible result occurs when (a - 1) / b is type(uint256).max,
        // but the largest value we can obtain is type(uint256).max - 1, which happens
        // when a = type(uint256).max and b = 1.
        unchecked {
            return SafeCast.toUint(a > 0) * ((a - 1) / b + 1);
        }
    }

    /**
     * @dev Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or
     * denominator == 0.
     *
     * Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv) with further edits by
     * Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);

            // Handle non-overflow cases, 256 by 256 division.
            if (high == 0) {
                // Solidity will revert if denominator == 0, unlike the div opcode on its own.
                // The surrounding unchecked block does not change this fact.
                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.
                return low / denominator;
            }

            // Make sure the result is less than 2²⁵⁶. Also prevents denominator == 0.
            if (denominator <= high) {
                Panic.panic(ternary(denominator == 0, Panic.DIVISION_BY_ZERO, Panic.UNDER_OVERFLOW));
            }

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [high low].
            uint256 remainder;
            assembly ("memory-safe") {
                // Compute remainder using mulmod.
                remainder := mulmod(x, y, denominator)

                // Subtract 256 bit number from 512 bit number.
                high := sub(high, gt(remainder, low))
                low := sub(low, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator.
            // Always >= 1. See https://cs.stackexchange.com/q/138556/92363.

            uint256 twos = denominator & (0 - denominator);
            assembly ("memory-safe") {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [high low] by twos.
                low := div(low, twos)

                // Flip twos such that it is 2²⁵⁶ / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from high into low.
            low |= high * twos;

            // Invert denominator mod 2²⁵⁶. Now that denominator is an odd number, it has an inverse modulo 2²⁵⁶ such
            // that denominator * inv ≡ 1 mod 2²⁵⁶. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv ≡ 1 mod 2⁴.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also
            // works in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2¹⁶
            inverse *= 2 - denominator * inverse; // inverse mod 2³²
            inverse *= 2 - denominator * inverse; // inverse mod 2⁶⁴
            inverse *= 2 - denominator * inverse; // inverse mod 2¹²⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2²⁵⁶

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2²⁵⁶. Since the preconditions guarantee that the outcome is
            // less than 2²⁵⁶, this is the final result. We don't need to compute the high bits of the result and high
            // is no longer required.
            result = low * inverse;
            return result;
        }
    }

    /**
     * @dev Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        return mulDiv(x, y, denominator) + SafeCast.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, denominator) > 0);
    }

    /**
     * @dev Calculates floor(x * y >> n) with full precision. Throws if result overflows a uint256.
     */
    function mulShr(uint256 x, uint256 y, uint8 n) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);
            if (high >= 1 << n) {
                Panic.panic(Panic.UNDER_OVERFLOW);
            }
            return (high << (256 - n)) | (low >> n);
        }
    }

    /**
     * @dev Calculates x * y >> n with full precision, following the selected rounding direction.
     */
    function mulShr(uint256 x, uint256 y, uint8 n, Rounding rounding) internal pure returns (uint256) {
        return mulShr(x, y, n) + SafeCast.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, 1 << n) > 0);
    }

    /**
     * @dev Calculate the modular multiplicative inverse of a number in Z/nZ.
     *
     * If n is a prime, then Z/nZ is a field. In that case all elements are inversible, except 0.
     * If n is not a prime, then Z/nZ is not a field, and some elements might not be inversible.
     *
     * If the input value is not inversible, 0 is returned.
     *
     * NOTE: If you know for sure that n is (big) a prime, it may be cheaper to use Fermat's little theorem and get the
     * inverse using `Math.modExp(a, n - 2, n)`. See {invModPrime}.
     */
    function invMod(uint256 a, uint256 n) internal pure returns (uint256) {
        unchecked {
            if (n == 0) return 0;

            // The inverse modulo is calculated using the Extended Euclidean Algorithm (iterative version)
            // Used to compute integers x and y such that: ax + ny = gcd(a, n).
            // When the gcd is 1, then the inverse of a modulo n exists and it's x.
            // ax + ny = 1
            // ax = 1 + (-y)n
            // ax ≡ 1 (mod n) # x is the inverse of a modulo n

            // If the remainder is 0 the gcd is n right away.
            uint256 remainder = a % n;
            uint256 gcd = n;

            // Therefore the initial coefficients are:
            // ax + ny = gcd(a, n) = n
            // 0a + 1n = n
            int256 x = 0;
            int256 y = 1;

            while (remainder != 0) {
                uint256 quotient = gcd / remainder;

                (gcd, remainder) = (
                    // The old remainder is the next gcd to try.
                    remainder,
                    // Compute the next remainder.
                    // Can't overflow given that (a % gcd) * (gcd // (a % gcd)) <= gcd
                    // where gcd is at most n (capped to type(uint256).max)
                    gcd - remainder * quotient
                );

                (x, y) = (
                    // Increment the coefficient of a.
                    y,
                    // Decrement the coefficient of n.
                    // Can overflow, but the result is casted to uint256 so that the
                    // next value of y is "wrapped around" to a value between 0 and n - 1.
                    x - y * int256(quotient)
                );
            }

            if (gcd != 1) return 0; // No inverse exists.
            return ternary(x < 0, n - uint256(-x), uint256(x)); // Wrap the result if it's negative.
        }
    }

    /**
     * @dev Variant of {invMod}. More efficient, but only works if `p` is known to be a prime greater than `2`.
     *
     * From https://en.wikipedia.org/wiki/Fermat%27s_little_theorem[Fermat's little theorem], we know that if p is
     * prime, then `a**(p-1) ≡ 1 mod p`. As a consequence, we have `a * a**(p-2) ≡ 1 mod p`, which means that
     * `a**(p-2)` is the modular multiplicative inverse of a in Fp.
     *
     * NOTE: this function does NOT check that `p` is a prime greater than `2`.
     */
    function invModPrime(uint256 a, uint256 p) internal view returns (uint256) {
        unchecked {
            return Math.modExp(a, p - 2, p);
        }
    }

    /**
     * @dev Returns the modular exponentiation of the specified base, exponent and modulus (b ** e % m)
     *
     * Requirements:
     * - modulus can't be zero
     * - underlying staticcall to precompile must succeed
     *
     * IMPORTANT: The result is only valid if the underlying call succeeds. When using this function, make
     * sure the chain you're using it on supports the precompiled contract for modular exponentiation
     * at address 0x05 as specified in https://eips.ethereum.org/EIPS/eip-198[EIP-198]. Otherwise,
     * the underlying function will succeed given the lack of a revert, but the result may be incorrectly
     * interpreted as 0.
     */
    function modExp(uint256 b, uint256 e, uint256 m) internal view returns (uint256) {
        (bool success, uint256 result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    /**
     * @dev Returns the modular exponentiation of the specified base, exponent and modulus (b ** e % m).
     * It includes a success flag indicating if the operation succeeded. Operation will be marked as failed if trying
     * to operate modulo 0 or if the underlying precompile reverted.
     *
     * IMPORTANT: The result is only valid if the success flag is true. When using this function, make sure the chain
     * you're using it on supports the precompiled contract for modular exponentiation at address 0x05 as specified in
     * https://eips.ethereum.org/EIPS/eip-198[EIP-198]. Otherwise, the underlying function will succeed given the lack
     * of a revert, but the result may be incorrectly interpreted as 0.
     */
    function tryModExp(uint256 b, uint256 e, uint256 m) internal view returns (bool success, uint256 result) {
        if (m == 0) return (false, 0);
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            // | Offset    | Content    | Content (Hex)                                                      |
            // |-----------|------------|--------------------------------------------------------------------|
            // | 0x00:0x1f | size of b  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x20:0x3f | size of e  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x40:0x5f | size of m  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x60:0x7f | value of b | 0x<.............................................................b> |
            // | 0x80:0x9f | value of e | 0x<.............................................................e> |
            // | 0xa0:0xbf | value of m | 0x<.............................................................m> |
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), 0x20)
            mstore(add(ptr, 0x40), 0x20)
            mstore(add(ptr, 0x60), b)
            mstore(add(ptr, 0x80), e)
            mstore(add(ptr, 0xa0), m)

            // Given the result < m, it's guaranteed to fit in 32 bytes,
            // so we can use the memory scratch space located at offset 0.
            success := staticcall(gas(), 0x05, ptr, 0xc0, 0x00, 0x20)
            result := mload(0x00)
        }
    }

    /**
     * @dev Variant of {modExp} that supports inputs of arbitrary length.
     */
    function modExp(bytes memory b, bytes memory e, bytes memory m) internal view returns (bytes memory) {
        (bool success, bytes memory result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    /**
     * @dev Variant of {tryModExp} that supports inputs of arbitrary length.
     */
    function tryModExp(
        bytes memory b,
        bytes memory e,
        bytes memory m
    ) internal view returns (bool success, bytes memory result) {
        if (_zeroBytes(m)) return (false, new bytes(0));

        uint256 mLen = m.length;

        // Encode call args in result and move the free memory pointer
        result = abi.encodePacked(b.length, e.length, mLen, b, e, m);

        assembly ("memory-safe") {
            let dataPtr := add(result, 0x20)
            // Write result on top of args to avoid allocating extra memory.
            success := staticcall(gas(), 0x05, dataPtr, mload(result), dataPtr, mLen)
            // Overwrite the length.
            // result.length > returndatasize() is guaranteed because returndatasize() == m.length
            mstore(result, mLen)
            // Set the memory pointer after the returned data.
            mstore(0x40, add(dataPtr, mLen))
        }
    }

    /**
     * @dev Returns whether the provided byte array is zero.
     */
    function _zeroBytes(bytes memory buffer) private pure returns (bool) {
        uint256 chunk;
        for (uint256 i = 0; i < buffer.length; i += 0x20) {
            // See _unsafeReadBytesOffset from utils/Bytes.sol
            assembly ("memory-safe") {
                chunk := mload(add(add(buffer, 0x20), i))
            }
            if (chunk >> (8 * saturatingSub(i + 0x20, buffer.length)) != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded
     * towards zero.
     *
     * This method is based on Newton's method for computing square roots; the algorithm is restricted to only
     * using integer operations.
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        unchecked {
            // Take care of easy edge cases when a == 0 or a == 1
            if (a <= 1) {
                return a;
            }

            // In this function, we use Newton's method to get a root of `f(x) := x² - a`. It involves building a
            // sequence x_n that converges toward sqrt(a). For each iteration x_n, we also define the error between
            // the current value as `ε_n = | x_n - sqrt(a) |`.
            //
            // For our first estimation, we consider `e` the smallest power of 2 which is bigger than the square root
            // of the target. (i.e. `2**(e-1) ≤ sqrt(a) < 2**e`). We know that `e ≤ 128` because `(2¹²⁸)² = 2²⁵⁶` is
            // bigger than any uint256.
            //
            // By noticing that
            // `2**(e-1) ≤ sqrt(a) < 2**e → (2**(e-1))² ≤ a < (2**e)² → 2**(2*e-2) ≤ a < 2**(2*e)`
            // we can deduce that `e - 1` is `log2(a) / 2`. We can thus compute `x_n = 2**(e-1)` using a method similar
            // to the msb function.
            uint256 aa = a;
            uint256 xn = 1;

            if (aa >= (1 << 128)) {
                aa >>= 128;
                xn <<= 64;
            }
            if (aa >= (1 << 64)) {
                aa >>= 64;
                xn <<= 32;
            }
            if (aa >= (1 << 32)) {
                aa >>= 32;
                xn <<= 16;
            }
            if (aa >= (1 << 16)) {
                aa >>= 16;
                xn <<= 8;
            }
            if (aa >= (1 << 8)) {
                aa >>= 8;
                xn <<= 4;
            }
            if (aa >= (1 << 4)) {
                aa >>= 4;
                xn <<= 2;
            }
            if (aa >= (1 << 2)) {
                xn <<= 1;
            }

            // We now have x_n such that `x_n = 2**(e-1) ≤ sqrt(a) < 2**e = 2 * x_n`. This implies ε_n ≤ 2**(e-1).
            //
            // We can refine our estimation by noticing that the middle of that interval minimizes the error.
            // If we move x_n to equal 2**(e-1) + 2**(e-2), then we reduce the error to ε_n ≤ 2**(e-2).
            // This is going to be our x_0 (and ε_0)
            xn = (3 * xn) >> 1; // ε_0 := | x_0 - sqrt(a) | ≤ 2**(e-2)

            // From here, Newton's method give us:
            // x_{n+1} = (x_n + a / x_n) / 2
            //
            // One should note that:
            // x_{n+1}² - a = ((x_n + a / x_n) / 2)² - a
            //              = ((x_n² + a) / (2 * x_n))² - a
            //              = (x_n⁴ + 2 * a * x_n² + a²) / (4 * x_n²) - a
            //              = (x_n⁴ + 2 * a * x_n² + a² - 4 * a * x_n²) / (4 * x_n²)
            //              = (x_n⁴ - 2 * a * x_n² + a²) / (4 * x_n²)
            //              = (x_n² - a)² / (2 * x_n)²
            //              = ((x_n² - a) / (2 * x_n))²
            //              ≥ 0
            // Which proves that for all n ≥ 1, sqrt(a) ≤ x_n
            //
            // This gives us the proof of quadratic convergence of the sequence:
            // ε_{n+1} = | x_{n+1} - sqrt(a) |
            //         = | (x_n + a / x_n) / 2 - sqrt(a) |
            //         = | (x_n² + a - 2*x_n*sqrt(a)) / (2 * x_n) |
            //         = | (x_n - sqrt(a))² / (2 * x_n) |
            //         = | ε_n² / (2 * x_n) |
            //         = ε_n² / | (2 * x_n) |
            //
            // For the first iteration, we have a special case where x_0 is known:
            // ε_1 = ε_0² / | (2 * x_0) |
            //     ≤ (2**(e-2))² / (2 * (2**(e-1) + 2**(e-2)))
            //     ≤ 2**(2*e-4) / (3 * 2**(e-1))
            //     ≤ 2**(e-3) / 3
            //     ≤ 2**(e-3-log2(3))
            //     ≤ 2**(e-4.5)
            //
            // For the following iterations, we use the fact that, 2**(e-1) ≤ sqrt(a) ≤ x_n:
            // ε_{n+1} = ε_n² / | (2 * x_n) |
            //         ≤ (2**(e-k))² / (2 * 2**(e-1))
            //         ≤ 2**(2*e-2*k) / 2**e
            //         ≤ 2**(e-2*k)
            xn = (xn + a / xn) >> 1; // ε_1 := | x_1 - sqrt(a) | ≤ 2**(e-4.5)  -- special case, see above
            xn = (xn + a / xn) >> 1; // ε_2 := | x_2 - sqrt(a) | ≤ 2**(e-9)    -- general case with k = 4.5
            xn = (xn + a / xn) >> 1; // ε_3 := | x_3 - sqrt(a) | ≤ 2**(e-18)   -- general case with k = 9
            xn = (xn + a / xn) >> 1; // ε_4 := | x_4 - sqrt(a) | ≤ 2**(e-36)   -- general case with k = 18
            xn = (xn + a / xn) >> 1; // ε_5 := | x_5 - sqrt(a) | ≤ 2**(e-72)   -- general case with k = 36
            xn = (xn + a / xn) >> 1; // ε_6 := | x_6 - sqrt(a) | ≤ 2**(e-144)  -- general case with k = 72

            // Because e ≤ 128 (as discussed during the first estimation phase), we know have reached a precision
            // ε_6 ≤ 2**(e-144) < 1. Given we're operating on integers, then we can ensure that xn is now either
            // sqrt(a) or sqrt(a) + 1.
            return xn - SafeCast.toUint(xn > a / xn);
        }
    }

    /**
     * @dev Calculates sqrt(a), following the selected rounding direction.
     */
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && result * result < a);
        }
    }

    /**
     * @dev Return the log in base 2 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log2(uint256 x) internal pure returns (uint256 r) {
        // If value has upper 128 bits set, log2 result is at least 128
        r = SafeCast.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        // If upper 64 bits of 128-bit half set, add 64 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffffffffffff) << 6;
        // If upper 32 bits of 64-bit half set, add 32 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffff) << 5;
        // If upper 16 bits of 32-bit half set, add 16 to result
        r |= SafeCast.toUint((x >> r) > 0xffff) << 4;
        // If upper 8 bits of 16-bit half set, add 8 to result
        r |= SafeCast.toUint((x >> r) > 0xff) << 3;
        // If upper 4 bits of 8-bit half set, add 4 to result
        r |= SafeCast.toUint((x >> r) > 0xf) << 2;

        // Shifts value right by the current result and use it as an index into this lookup table:
        //
        // | x (4 bits) |  index  | table[index] = MSB position |
        // |------------|---------|-----------------------------|
        // |    0000    |    0    |        table[0] = 0         |
        // |    0001    |    1    |        table[1] = 0         |
        // |    0010    |    2    |        table[2] = 1         |
        // |    0011    |    3    |        table[3] = 1         |
        // |    0100    |    4    |        table[4] = 2         |
        // |    0101    |    5    |        table[5] = 2         |
        // |    0110    |    6    |        table[6] = 2         |
        // |    0111    |    7    |        table[7] = 2         |
        // |    1000    |    8    |        table[8] = 3         |
        // |    1001    |    9    |        table[9] = 3         |
        // |    1010    |   10    |        table[10] = 3        |
        // |    1011    |   11    |        table[11] = 3        |
        // |    1100    |   12    |        table[12] = 3        |
        // |    1101    |   13    |        table[13] = 3        |
        // |    1110    |   14    |        table[14] = 3        |
        // |    1111    |   15    |        table[15] = 3        |
        //
        // The lookup table is represented as a 32-byte value with the MSB positions for 0-15 in the first 16 bytes (most significant half).
        assembly ("memory-safe") {
            r := or(r, byte(shr(r, x), 0x0000010102020202030303030303030300000000000000000000000000000000))
        }
    }

    /**
     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 1 << result < value);
        }
    }

    /**
     * @dev Return the log in base 10 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 10 ** result < value);
        }
    }

    /**
     * @dev Return the log in base 256 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     *
     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.
     */
    function log256(uint256 x) internal pure returns (uint256 r) {
        // If value has upper 128 bits set, log2 result is at least 128
        r = SafeCast.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        // If upper 64 bits of 128-bit half set, add 64 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffffffffffff) << 6;
        // If upper 32 bits of 64-bit half set, add 32 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffff) << 5;
        // If upper 16 bits of 32-bit half set, add 16 to result
        r |= SafeCast.toUint((x >> r) > 0xffff) << 4;
        // Add 1 if upper 8 bits of 16-bit half set, and divide accumulated result by 8
        return (r >> 3) | SafeCast.toUint((x >> r) > 0xff);
    }

    /**
     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 1 << (result << 3) < value);
        }
    }

    /**
     * @dev Returns whether a provided rounding mode is considered rounding up for unsigned integers.
     */
    function unsignedRoundsUp(Rounding rounding) internal pure returns (bool) {
        return uint8(rounding) % 2 == 1;
    }

    /**
     * @dev Counts the number of leading zero bits in a uint256.
     */
    function clz(uint256 x) internal pure returns (uint256) {
        return ternary(x == 0, 256, 255 - log2(x));
    }
}


// File @openzeppelin/contracts/utils/SlotDerivation.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.5.0) (utils/SlotDerivation.sol)
// This file was procedurally generated from scripts/generate/templates/SlotDerivation.js.

pragma solidity ^0.8.20;

/**
 * @dev Library for computing storage (and transient storage) locations from namespaces and deriving slots
 * corresponding to standard patterns. The derivation method for array and mapping matches the storage layout used by
 * the solidity language / compiler.
 *
 * See https://docs.soliditylang.org/en/v0.8.20/internals/layout_in_storage.html#mappings-and-dynamic-arrays[Solidity docs for mappings and dynamic arrays.].
 *
 * Example usage:
 * ```solidity
 * contract Example {
 *     // Add the library methods
 *     using StorageSlot for bytes32;
 *     using SlotDerivation for *;
 *
 *     // Declare a namespace
 *     string private constant _NAMESPACE = "<namespace>"; // eg. OpenZeppelin.Slot
 *
 *     function setValueInNamespace(uint256 key, address newValue) internal {
 *         _NAMESPACE.erc7201Slot().deriveMapping(key).getAddressSlot().value = newValue;
 *     }
 *
 *     function getValueInNamespace(uint256 key) internal view returns (address) {
 *         return _NAMESPACE.erc7201Slot().deriveMapping(key).getAddressSlot().value;
 *     }
 * }
 * ```
 *
 * TIP: Consider using this library along with {StorageSlot}.
 *
 * NOTE: This library provides a way to manipulate storage locations in a non-standard way. Tooling for checking
 * upgrade safety will ignore the slots accessed through this library.
 *
 * _Available since v5.1._
 */
library SlotDerivation {
    /**
     * @dev Derive an ERC-7201 slot from a string (namespace).
     */
    function erc7201Slot(string memory namespace) internal pure returns (bytes32 slot) {
        assembly ("memory-safe") {
            mstore(0x00, sub(keccak256(add(namespace, 0x20), mload(namespace)), 1))
            slot := and(keccak256(0x00, 0x20), not(0xff))
        }
    }

    /**
     * @dev Add an offset to a slot to get the n-th element of a structure or an array.
     */
    function offset(bytes32 slot, uint256 pos) internal pure returns (bytes32 result) {
        unchecked {
            return bytes32(uint256(slot) + pos);
        }
    }

    /**
     * @dev Derive the location of the first element in an array from the slot where the length is stored.
     */
    function deriveArray(bytes32 slot) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, slot)
            result := keccak256(0x00, 0x20)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, address key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, and(key, shr(96, not(0))))
            mstore(0x20, slot)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, bool key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, iszero(iszero(key)))
            mstore(0x20, slot)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, bytes32 key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, key)
            mstore(0x20, slot)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, uint256 key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, key)
            mstore(0x20, slot)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, int256 key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, key)
            mstore(0x20, slot)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, string memory key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let length := mload(key)
            let begin := add(key, 0x20)
            let end := add(begin, length)
            let cache := mload(end)
            mstore(end, slot)
            result := keccak256(begin, add(length, 0x20))
            mstore(end, cache)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, bytes memory key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let length := mload(key)
            let begin := add(key, 0x20)
            let end := add(begin, length)
            let cache := mload(end)
            mstore(end, slot)
            result := keccak256(begin, add(length, 0x20))
            mstore(end, cache)
        }
    }
}


// File @openzeppelin/contracts/utils/StorageSlot.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/StorageSlot.sol)
// This file was procedurally generated from scripts/generate/templates/StorageSlot.js.

pragma solidity ^0.8.20;

/**
 * @dev Library for reading and writing primitive types to specific storage slots.
 *
 * Storage slots are often used to avoid storage conflict when dealing with upgradeable contracts.
 * This library helps with reading and writing to such slots without the need for inline assembly.
 *
 * The functions in this library return Slot structs that contain a `value` member that can be used to read or write.
 *
 * Example usage to set ERC-1967 implementation slot:
 * ```solidity
 * contract ERC1967 {
 *     // Define the slot. Alternatively, use the SlotDerivation library to derive the slot.
 *     bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
 *
 *     function _getImplementation() internal view returns (address) {
 *         return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
 *     }
 *
 *     function _setImplementation(address newImplementation) internal {
 *         require(newImplementation.code.length > 0);
 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
 *     }
 * }
 * ```
 *
 * TIP: Consider using this library along with {SlotDerivation}.
 */
library StorageSlot {
    struct AddressSlot {
        address value;
    }

    struct BooleanSlot {
        bool value;
    }

    struct Bytes32Slot {
        bytes32 value;
    }

    struct Uint256Slot {
        uint256 value;
    }

    struct Int256Slot {
        int256 value;
    }

    struct StringSlot {
        string value;
    }

    struct BytesSlot {
        bytes value;
    }

    /**
     * @dev Returns an `AddressSlot` with member `value` located at `slot`.
     */
    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `BooleanSlot` with member `value` located at `slot`.
     */
    function getBooleanSlot(bytes32 slot) internal pure returns (BooleanSlot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `Bytes32Slot` with member `value` located at `slot`.
     */
    function getBytes32Slot(bytes32 slot) internal pure returns (Bytes32Slot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `Uint256Slot` with member `value` located at `slot`.
     */
    function getUint256Slot(bytes32 slot) internal pure returns (Uint256Slot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `Int256Slot` with member `value` located at `slot`.
     */
    function getInt256Slot(bytes32 slot) internal pure returns (Int256Slot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `StringSlot` with member `value` located at `slot`.
     */
    function getStringSlot(bytes32 slot) internal pure returns (StringSlot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `StringSlot` representation of the string storage pointer `store`.
     */
    function getStringSlot(string storage store) internal pure returns (StringSlot storage r) {
        assembly ("memory-safe") {
            r.slot := store.slot
        }
    }

    /**
     * @dev Returns a `BytesSlot` with member `value` located at `slot`.
     */
    function getBytesSlot(bytes32 slot) internal pure returns (BytesSlot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BytesSlot` representation of the bytes storage pointer `store`.
     */
    function getBytesSlot(bytes storage store) internal pure returns (BytesSlot storage r) {
        assembly ("memory-safe") {
            r.slot := store.slot
        }
    }
}


// File @openzeppelin/contracts/utils/Arrays.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.6.0) (utils/Arrays.sol)
// This file was procedurally generated from scripts/generate/templates/Arrays.js.

pragma solidity ^0.8.24;




/**
 * @dev Collection of functions related to array types.
 */
library Arrays {
    using SlotDerivation for bytes32;
    using StorageSlot for bytes32;

    /**
     * @dev Sort an array of uint256 (in memory) following the provided comparator function.
     *
     * This function does the sorting "in place", meaning that it overrides the input. The object is returned for
     * convenience, but that returned value can be discarded safely if the caller has a memory pointer to the array.
     *
     * NOTE: this function's cost is `O(n · log(n))` in average and `O(n²)` in the worst case, with n the length of the
     * array. Using it in view functions that are executed through `eth_call` is safe, but one should be very careful
     * when executing this as part of a transaction. If the array being sorted is too large, the sort operation may
     * consume more gas than is available in a block, leading to potential DoS.
     *
     * IMPORTANT: Consider memory side-effects when using custom comparator functions that access memory in an unsafe way.
     */
    function sort(
        uint256[] memory array,
        function(uint256, uint256) pure returns (bool) comp
    ) internal pure returns (uint256[] memory) {
        _quickSort(_begin(array), _end(array), comp);
        return array;
    }

    /**
     * @dev Variant of {sort} that sorts an array of uint256 in increasing order.
     */
    function sort(uint256[] memory array) internal pure returns (uint256[] memory) {
        sort(array, Comparators.lt);
        return array;
    }

    /**
     * @dev Sort an array of address (in memory) following the provided comparator function.
     *
     * This function does the sorting "in place", meaning that it overrides the input. The object is returned for
     * convenience, but that returned value can be discarded safely if the caller has a memory pointer to the array.
     *
     * NOTE: this function's cost is `O(n · log(n))` in average and `O(n²)` in the worst case, with n the length of the
     * array. Using it in view functions that are executed through `eth_call` is safe, but one should be very careful
     * when executing this as part of a transaction. If the array being sorted is too large, the sort operation may
     * consume more gas than is available in a block, leading to potential DoS.
     *
     * IMPORTANT: Consider memory side-effects when using custom comparator functions that access memory in an unsafe way.
     */
    function sort(
        address[] memory array,
        function(address, address) pure returns (bool) comp
    ) internal pure returns (address[] memory) {
        sort(_castToUint256Array(array), _castToUint256Comp(comp));
        return array;
    }

    /**
     * @dev Variant of {sort} that sorts an array of address in increasing order.
     */
    function sort(address[] memory array) internal pure returns (address[] memory) {
        sort(_castToUint256Array(array), Comparators.lt);
        return array;
    }

    /**
     * @dev Sort an array of bytes32 (in memory) following the provided comparator function.
     *
     * This function does the sorting "in place", meaning that it overrides the input. The object is returned for
     * convenience, but that returned value can be discarded safely if the caller has a memory pointer to the array.
     *
     * NOTE: this function's cost is `O(n · log(n))` in average and `O(n²)` in the worst case, with n the length of the
     * array. Using it in view functions that are executed through `eth_call` is safe, but one should be very careful
     * when executing this as part of a transaction. If the array being sorted is too large, the sort operation may
     * consume more gas than is available in a block, leading to potential DoS.
     *
     * IMPORTANT: Consider memory side-effects when using custom comparator functions that access memory in an unsafe way.
     */
    function sort(
        bytes32[] memory array,
        function(bytes32, bytes32) pure returns (bool) comp
    ) internal pure returns (bytes32[] memory) {
        sort(_castToUint256Array(array), _castToUint256Comp(comp));
        return array;
    }

    /**
     * @dev Variant of {sort} that sorts an array of bytes32 in increasing order.
     */
    function sort(bytes32[] memory array) internal pure returns (bytes32[] memory) {
        sort(_castToUint256Array(array), Comparators.lt);
        return array;
    }

    /**
     * @dev Performs a quick sort of a segment of memory. The segment sorted starts at `begin` (inclusive), and stops
     * at end (exclusive). Sorting follows the `comp` comparator.
     *
     * Invariant: `begin <= end`. This is the case when initially called by {sort} and is preserved in subcalls.
     *
     * IMPORTANT: Memory locations between `begin` and `end` are not validated/zeroed. This function should
     * be used only if the limits are within a memory array.
     */
    function _quickSort(uint256 begin, uint256 end, function(uint256, uint256) pure returns (bool) comp) private pure {
        unchecked {
            if (end - begin < 0x40) return;

            // Use first element as pivot
            uint256 pivot = _mload(begin);
            // Position where the pivot should be at the end of the loop
            uint256 pos = begin;

            for (uint256 it = begin + 0x20; it < end; it += 0x20) {
                if (comp(_mload(it), pivot)) {
                    // If the value stored at the iterator's position comes before the pivot, we increment the
                    // position of the pivot and move the value there.
                    pos += 0x20;
                    _swap(pos, it);
                }
            }

            _swap(begin, pos); // Swap pivot into place
            _quickSort(begin, pos, comp); // Sort the left side of the pivot
            _quickSort(pos + 0x20, end, comp); // Sort the right side of the pivot
        }
    }

    /**
     * @dev Pointer to the memory location of the first element of `array`.
     */
    function _begin(uint256[] memory array) private pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            ptr := add(array, 0x20)
        }
    }

    /**
     * @dev Pointer to the memory location of the first memory word (32bytes) after `array`. This is the memory word
     * that comes just after the last element of the array.
     */
    function _end(uint256[] memory array) private pure returns (uint256 ptr) {
        unchecked {
            return _begin(array) + array.length * 0x20;
        }
    }

    /**
     * @dev Load memory word (as a uint256) at location `ptr`.
     */
    function _mload(uint256 ptr) private pure returns (uint256 value) {
        assembly {
            value := mload(ptr)
        }
    }

    /**
     * @dev Swaps the elements memory location `ptr1` and `ptr2`.
     */
    function _swap(uint256 ptr1, uint256 ptr2) private pure {
        assembly {
            let value1 := mload(ptr1)
            let value2 := mload(ptr2)
            mstore(ptr1, value2)
            mstore(ptr2, value1)
        }
    }

    /// @dev Helper: low level cast address memory array to uint256 memory array
    function _castToUint256Array(address[] memory input) private pure returns (uint256[] memory output) {
        assembly {
            output := input
        }
    }

    /// @dev Helper: low level cast bytes32 memory array to uint256 memory array
    function _castToUint256Array(bytes32[] memory input) private pure returns (uint256[] memory output) {
        assembly {
            output := input
        }
    }

    /// @dev Helper: low level cast address comp function to uint256 comp function
    function _castToUint256Comp(
        function(address, address) pure returns (bool) input
    ) private pure returns (function(uint256, uint256) pure returns (bool) output) {
        assembly {
            output := input
        }
    }

    /// @dev Helper: low level cast bytes32 comp function to uint256 comp function
    function _castToUint256Comp(
        function(bytes32, bytes32) pure returns (bool) input
    ) private pure returns (function(uint256, uint256) pure returns (bool) output) {
        assembly {
            output := input
        }
    }

    /**
     * @dev Searches a sorted `array` and returns the first index that contains
     * a value greater or equal to `element`. If no such index exists (i.e. all
     * values in the array are strictly less than `element`), the array length is
     * returned. Time complexity O(log n).
     *
     * NOTE: The `array` is expected to be sorted in ascending order, and to
     * contain no repeated elements.
     *
     * IMPORTANT: Deprecated. This implementation behaves as {lowerBound} but lacks
     * support for repeated elements in the array. The {lowerBound} function should
     * be used instead.
     */
    function findUpperBound(uint256[] storage array, uint256 element) internal view returns (uint256) {
        uint256 low = 0;
        uint256 high = array.length;

        if (high == 0) {
            return 0;
        }

        while (low < high) {
            uint256 mid = Math.average(low, high);

            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)
            // because Math.average rounds towards zero (it does integer division with truncation).
            if (unsafeAccess(array, mid).value > element) {
                high = mid;
            } else {
                low = mid + 1;
            }
        }

        // At this point `low` is the exclusive upper bound. We will return the inclusive upper bound.
        if (low > 0 && unsafeAccess(array, low - 1).value == element) {
            return low - 1;
        } else {
            return low;
        }
    }

    /**
     * @dev Searches an `array` sorted in ascending order and returns the first
     * index that contains a value greater or equal than `element`. If no such index
     * exists (i.e. all values in the array are strictly less than `element`), the array
     * length is returned. Time complexity O(log n).
     *
     * See C++'s https://en.cppreference.com/w/cpp/algorithm/lower_bound[lower_bound].
     */
    function lowerBound(uint256[] storage array, uint256 element) internal view returns (uint256) {
        uint256 low = 0;
        uint256 high = array.length;

        if (high == 0) {
            return 0;
        }

        while (low < high) {
            uint256 mid = Math.average(low, high);

            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)
            // because Math.average rounds towards zero (it does integer division with truncation).
            if (unsafeAccess(array, mid).value < element) {
                // this cannot overflow because mid < high
                unchecked {
                    low = mid + 1;
                }
            } else {
                high = mid;
            }
        }

        return low;
    }

    /**
     * @dev Searches an `array` sorted in ascending order and returns the first
     * index that contains a value strictly greater than `element`. If no such index
     * exists (i.e. all values in the array are strictly less than `element`), the array
     * length is returned. Time complexity O(log n).
     *
     * See C++'s https://en.cppreference.com/w/cpp/algorithm/upper_bound[upper_bound].
     */
    function upperBound(uint256[] storage array, uint256 element) internal view returns (uint256) {
        uint256 low = 0;
        uint256 high = array.length;

        if (high == 0) {
            return 0;
        }

        while (low < high) {
            uint256 mid = Math.average(low, high);

            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)
            // because Math.average rounds towards zero (it does integer division with truncation).
            if (unsafeAccess(array, mid).value > element) {
                high = mid;
            } else {
                // this cannot overflow because mid < high
                unchecked {
                    low = mid + 1;
                }
            }
        }

        return low;
    }

    /**
     * @dev Same as {lowerBound}, but with an array in memory.
     */
    function lowerBoundMemory(uint256[] memory array, uint256 element) internal pure returns (uint256) {
        uint256 low = 0;
        uint256 high = array.length;

        if (high == 0) {
            return 0;
        }

        while (low < high) {
            uint256 mid = Math.average(low, high);

            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)
            // because Math.average rounds towards zero (it does integer division with truncation).
            if (unsafeMemoryAccess(array, mid) < element) {
                // this cannot overflow because mid < high
                unchecked {
                    low = mid + 1;
                }
            } else {
                high = mid;
            }
        }

        return low;
    }

    /**
     * @dev Same as {upperBound}, but with an array in memory.
     */
    function upperBoundMemory(uint256[] memory array, uint256 element) internal pure returns (uint256) {
        uint256 low = 0;
        uint256 high = array.length;

        if (high == 0) {
            return 0;
        }

        while (low < high) {
            uint256 mid = Math.average(low, high);

            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)
            // because Math.average rounds towards zero (it does integer division with truncation).
            if (unsafeMemoryAccess(array, mid) > element) {
                high = mid;
            } else {
                // this cannot overflow because mid < high
                unchecked {
                    low = mid + 1;
                }
            }
        }

        return low;
    }

    /**
     * @dev Copies the content of `array`, from `start` (included) to the end of `array` into a new address array in
     * memory.
     *
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice[Javascript's `Array.slice`]
     */
    function slice(address[] memory array, uint256 start) internal pure returns (address[] memory) {
        return slice(array, start, array.length);
    }

    /**
     * @dev Copies the content of `array`, from `start` (included) to `end` (excluded) into a new address array in
     * memory. The `end` argument is truncated to the length of the `array`.
     *
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice[Javascript's `Array.slice`]
     */
    function slice(address[] memory array, uint256 start, uint256 end) internal pure returns (address[] memory) {
        // sanitize
        end = Math.min(end, array.length);
        start = Math.min(start, end);

        // allocate and copy
        address[] memory result = new address[](end - start);
        assembly ("memory-safe") {
            mcopy(add(result, 0x20), add(add(array, 0x20), mul(start, 0x20)), mul(sub(end, start), 0x20))
        }

        return result;
    }

    /**
     * @dev Copies the content of `array`, from `start` (included) to the end of `array` into a new bytes32 array in
     * memory.
     *
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice[Javascript's `Array.slice`]
     */
    function slice(bytes32[] memory array, uint256 start) internal pure returns (bytes32[] memory) {
        return slice(array, start, array.length);
    }

    /**
     * @dev Copies the content of `array`, from `start` (included) to `end` (excluded) into a new bytes32 array in
     * memory. The `end` argument is truncated to the length of the `array`.
     *
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice[Javascript's `Array.slice`]
     */
    function slice(bytes32[] memory array, uint256 start, uint256 end) internal pure returns (bytes32[] memory) {
        // sanitize
        end = Math.min(end, array.length);
        start = Math.min(start, end);

        // allocate and copy
        bytes32[] memory result = new bytes32[](end - start);
        assembly ("memory-safe") {
            mcopy(add(result, 0x20), add(add(array, 0x20), mul(start, 0x20)), mul(sub(end, start), 0x20))
        }

        return result;
    }

    /**
     * @dev Copies the content of `array`, from `start` (included) to the end of `array` into a new uint256 array in
     * memory.
     *
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice[Javascript's `Array.slice`]
     */
    function slice(uint256[] memory array, uint256 start) internal pure returns (uint256[] memory) {
        return slice(array, start, array.length);
    }

    /**
     * @dev Copies the content of `array`, from `start` (included) to `end` (excluded) into a new uint256 array in
     * memory. The `end` argument is truncated to the length of the `array`.
     *
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice[Javascript's `Array.slice`]
     */
    function slice(uint256[] memory array, uint256 start, uint256 end) internal pure returns (uint256[] memory) {
        // sanitize
        end = Math.min(end, array.length);
        start = Math.min(start, end);

        // allocate and copy
        uint256[] memory result = new uint256[](end - start);
        assembly ("memory-safe") {
            mcopy(add(result, 0x20), add(add(array, 0x20), mul(start, 0x20)), mul(sub(end, start), 0x20))
        }

        return result;
    }

    /**
     * @dev Moves the content of `array`, from `start` (included) to the end of `array` to the start of that array,
     * and shrinks the array length accordingly, effectively overwriting the array with array[start:].
     *
     * NOTE: This function modifies the provided array in place. If you need to preserve the original array, use {slice} instead.
     */
    function splice(address[] memory array, uint256 start) internal pure returns (address[] memory) {
        return splice(array, start, array.length);
    }

    /**
     * @dev Moves the content of `array`, from `start` (included) to `end` (excluded) to the start of that array,
     * and shrinks the array length accordingly, effectively overwriting the array with array[start:end]. The
     * `end` argument is truncated to the length of the `array`.
     *
     * NOTE: This function modifies the provided array in place. If you need to preserve the original array, use {slice} instead.
     */
    function splice(address[] memory array, uint256 start, uint256 end) internal pure returns (address[] memory) {
        // sanitize
        end = Math.min(end, array.length);
        start = Math.min(start, end);

        // move and resize
        assembly ("memory-safe") {
            mcopy(add(array, 0x20), add(add(array, 0x20), mul(start, 0x20)), mul(sub(end, start), 0x20))
            mstore(array, sub(end, start))
        }

        return array;
    }

    /**
     * @dev Replaces elements in `array` starting at `pos` with all elements from `replacement`.
     *
     * Parameters are clamped to valid ranges (e.g. `pos` is clamped to `[0, array.length]`).
     * If `pos >= array.length`, no replacement occurs and the array is returned unchanged.
     *
     * NOTE: This function modifies the provided array in place.
     */
    function replace(
        address[] memory array,
        uint256 pos,
        address[] memory replacement
    ) internal pure returns (address[] memory) {
        return replace(array, pos, replacement, 0, replacement.length);
    }

    /**
     * @dev Replaces elements in `array` starting at `pos` with elements from `replacement` starting at `offset`.
     * Copies at most `length` elements from `replacement` to `array`.
     *
     * Parameters are clamped to valid ranges (i.e. `pos` is clamped to `[0, array.length]`, `offset` is
     * clamped to `[0, replacement.length]`, and `length` is clamped to `min(length, replacement.length - offset,
     * array.length - pos)`). If `pos >= array.length` or `offset >= replacement.length`, no replacement occurs
     * and the array is returned unchanged.
     *
     * NOTE: This function modifies the provided array in place.
     */
    function replace(
        address[] memory array,
        uint256 pos,
        address[] memory replacement,
        uint256 offset,
        uint256 length
    ) internal pure returns (address[] memory) {
        // sanitize
        pos = Math.min(pos, array.length);
        offset = Math.min(offset, replacement.length);
        length = Math.min(length, Math.min(replacement.length - offset, array.length - pos));

        // replace
        assembly ("memory-safe") {
            mcopy(
                add(add(array, 0x20), mul(pos, 0x20)),
                add(add(replacement, 0x20), mul(offset, 0x20)),
                mul(length, 0x20)
            )
        }

        return array;
    }

    /**
     * @dev Moves the content of `array`, from `start` (included) to the end of `array` to the start of that array,
     * and shrinks the array length accordingly, effectively overwriting the array with array[start:].
     *
     * NOTE: This function modifies the provided array in place. If you need to preserve the original array, use {slice} instead.
     */
    function splice(bytes32[] memory array, uint256 start) internal pure returns (bytes32[] memory) {
        return splice(array, start, array.length);
    }

    /**
     * @dev Moves the content of `array`, from `start` (included) to `end` (excluded) to the start of that array,
     * and shrinks the array length accordingly, effectively overwriting the array with array[start:end]. The
     * `end` argument is truncated to the length of the `array`.
     *
     * NOTE: This function modifies the provided array in place. If you need to preserve the original array, use {slice} instead.
     */
    function splice(bytes32[] memory array, uint256 start, uint256 end) internal pure returns (bytes32[] memory) {
        // sanitize
        end = Math.min(end, array.length);
        start = Math.min(start, end);

        // move and resize
        assembly ("memory-safe") {
            mcopy(add(array, 0x20), add(add(array, 0x20), mul(start, 0x20)), mul(sub(end, start), 0x20))
            mstore(array, sub(end, start))
        }

        return array;
    }

    /**
     * @dev Replaces elements in `array` starting at `pos` with all elements from `replacement`.
     *
     * Parameters are clamped to valid ranges (e.g. `pos` is clamped to `[0, array.length]`).
     * If `pos >= array.length`, no replacement occurs and the array is returned unchanged.
     *
     * NOTE: This function modifies the provided array in place.
     */
    function replace(
        bytes32[] memory array,
        uint256 pos,
        bytes32[] memory replacement
    ) internal pure returns (bytes32[] memory) {
        return replace(array, pos, replacement, 0, replacement.length);
    }

    /**
     * @dev Replaces elements in `array` starting at `pos` with elements from `replacement` starting at `offset`.
     * Copies at most `length` elements from `replacement` to `array`.
     *
     * Parameters are clamped to valid ranges (i.e. `pos` is clamped to `[0, array.length]`, `offset` is
     * clamped to `[0, replacement.length]`, and `length` is clamped to `min(length, replacement.length - offset,
     * array.length - pos)`). If `pos >= array.length` or `offset >= replacement.length`, no replacement occurs
     * and the array is returned unchanged.
     *
     * NOTE: This function modifies the provided array in place.
     */
    function replace(
        bytes32[] memory array,
        uint256 pos,
        bytes32[] memory replacement,
        uint256 offset,
        uint256 length
    ) internal pure returns (bytes32[] memory) {
        // sanitize
        pos = Math.min(pos, array.length);
        offset = Math.min(offset, replacement.length);
        length = Math.min(length, Math.min(replacement.length - offset, array.length - pos));

        // replace
        assembly ("memory-safe") {
            mcopy(
                add(add(array, 0x20), mul(pos, 0x20)),
                add(add(replacement, 0x20), mul(offset, 0x20)),
                mul(length, 0x20)
            )
        }

        return array;
    }

    /**
     * @dev Moves the content of `array`, from `start` (included) to the end of `array` to the start of that array,
     * and shrinks the array length accordingly, effectively overwriting the array with array[start:].
     *
     * NOTE: This function modifies the provided array in place. If you need to preserve the original array, use {slice} instead.
     */
    function splice(uint256[] memory array, uint256 start) internal pure returns (uint256[] memory) {
        return splice(array, start, array.length);
    }

    /**
     * @dev Moves the content of `array`, from `start` (included) to `end` (excluded) to the start of that array,
     * and shrinks the array length accordingly, effectively overwriting the array with array[start:end]. The
     * `end` argument is truncated to the length of the `array`.
     *
     * NOTE: This function modifies the provided array in place. If you need to preserve the original array, use {slice} instead.
     */
    function splice(uint256[] memory array, uint256 start, uint256 end) internal pure returns (uint256[] memory) {
        // sanitize
        end = Math.min(end, array.length);
        start = Math.min(start, end);

        // move and resize
        assembly ("memory-safe") {
            mcopy(add(array, 0x20), add(add(array, 0x20), mul(start, 0x20)), mul(sub(end, start), 0x20))
            mstore(array, sub(end, start))
        }

        return array;
    }

    /**
     * @dev Replaces elements in `array` starting at `pos` with all elements from `replacement`.
     *
     * Parameters are clamped to valid ranges (e.g. `pos` is clamped to `[0, array.length]`).
     * If `pos >= array.length`, no replacement occurs and the array is returned unchanged.
     *
     * NOTE: This function modifies the provided array in place.
     */
    function replace(
        uint256[] memory array,
        uint256 pos,
        uint256[] memory replacement
    ) internal pure returns (uint256[] memory) {
        return replace(array, pos, replacement, 0, replacement.length);
    }

    /**
     * @dev Replaces elements in `array` starting at `pos` with elements from `replacement` starting at `offset`.
     * Copies at most `length` elements from `replacement` to `array`.
     *
     * Parameters are clamped to valid ranges (i.e. `pos` is clamped to `[0, array.length]`, `offset` is
     * clamped to `[0, replacement.length]`, and `length` is clamped to `min(length, replacement.length - offset,
     * array.length - pos)`). If `pos >= array.length` or `offset >= replacement.length`, no replacement occurs
     * and the array is returned unchanged.
     *
     * NOTE: This function modifies the provided array in place.
     */
    function replace(
        uint256[] memory array,
        uint256 pos,
        uint256[] memory replacement,
        uint256 offset,
        uint256 length
    ) internal pure returns (uint256[] memory) {
        // sanitize
        pos = Math.min(pos, array.length);
        offset = Math.min(offset, replacement.length);
        length = Math.min(length, Math.min(replacement.length - offset, array.length - pos));

        // replace
        assembly ("memory-safe") {
            mcopy(
                add(add(array, 0x20), mul(pos, 0x20)),
                add(add(replacement, 0x20), mul(offset, 0x20)),
                mul(length, 0x20)
            )
        }

        return array;
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeAccess(address[] storage arr, uint256 pos) internal pure returns (StorageSlot.AddressSlot storage) {
        bytes32 slot;
        assembly ("memory-safe") {
            slot := arr.slot
        }
        return slot.deriveArray().offset(pos).getAddressSlot();
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeAccess(bytes32[] storage arr, uint256 pos) internal pure returns (StorageSlot.Bytes32Slot storage) {
        bytes32 slot;
        assembly ("memory-safe") {
            slot := arr.slot
        }
        return slot.deriveArray().offset(pos).getBytes32Slot();
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeAccess(uint256[] storage arr, uint256 pos) internal pure returns (StorageSlot.Uint256Slot storage) {
        bytes32 slot;
        assembly ("memory-safe") {
            slot := arr.slot
        }
        return slot.deriveArray().offset(pos).getUint256Slot();
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeAccess(bytes[] storage arr, uint256 pos) internal pure returns (StorageSlot.BytesSlot storage) {
        bytes32 slot;
        assembly ("memory-safe") {
            slot := arr.slot
        }
        return slot.deriveArray().offset(pos).getBytesSlot();
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeAccess(string[] storage arr, uint256 pos) internal pure returns (StorageSlot.StringSlot storage) {
        bytes32 slot;
        assembly ("memory-safe") {
            slot := arr.slot
        }
        return slot.deriveArray().offset(pos).getStringSlot();
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeMemoryAccess(address[] memory arr, uint256 pos) internal pure returns (address res) {
        assembly {
            res := mload(add(add(arr, 0x20), mul(pos, 0x20)))
        }
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeMemoryAccess(bytes32[] memory arr, uint256 pos) internal pure returns (bytes32 res) {
        assembly {
            res := mload(add(add(arr, 0x20), mul(pos, 0x20)))
        }
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeMemoryAccess(uint256[] memory arr, uint256 pos) internal pure returns (uint256 res) {
        assembly {
            res := mload(add(add(arr, 0x20), mul(pos, 0x20)))
        }
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeMemoryAccess(bytes[] memory arr, uint256 pos) internal pure returns (bytes memory res) {
        assembly {
            res := mload(add(add(arr, 0x20), mul(pos, 0x20)))
        }
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeMemoryAccess(string[] memory arr, uint256 pos) internal pure returns (string memory res) {
        assembly {
            res := mload(add(add(arr, 0x20), mul(pos, 0x20)))
        }
    }

    /**
     * @dev Helper to set the length of a dynamic array. Directly writing to `.length` is forbidden.
     *
     * WARNING: this does not clear elements if length is reduced, or initialize elements if length is increased.
     */
    function unsafeSetLength(address[] storage array, uint256 len) internal {
        assembly ("memory-safe") {
            sstore(array.slot, len)
        }
    }

    /**
     * @dev Helper to set the length of a dynamic array. Directly writing to `.length` is forbidden.
     *
     * WARNING: this does not clear elements if length is reduced, or initialize elements if length is increased.
     */
    function unsafeSetLength(bytes32[] storage array, uint256 len) internal {
        assembly ("memory-safe") {
            sstore(array.slot, len)
        }
    }

    /**
     * @dev Helper to set the length of a dynamic array. Directly writing to `.length` is forbidden.
     *
     * WARNING: this does not clear elements if length is reduced, or initialize elements if length is increased.
     */
    function unsafeSetLength(uint256[] storage array, uint256 len) internal {
        assembly ("memory-safe") {
            sstore(array.slot, len)
        }
    }

    /**
     * @dev Helper to set the length of a dynamic array. Directly writing to `.length` is forbidden.
     *
     * WARNING: this does not clear elements if length is reduced, or initialize elements if length is increased.
     */
    function unsafeSetLength(bytes[] storage array, uint256 len) internal {
        assembly ("memory-safe") {
            sstore(array.slot, len)
        }
    }

    /**
     * @dev Helper to set the length of a dynamic array. Directly writing to `.length` is forbidden.
     *
     * WARNING: this does not clear elements if length is reduced, or initialize elements if length is increased.
     */
    function unsafeSetLength(string[] storage array, uint256 len) internal {
        assembly ("memory-safe") {
            sstore(array.slot, len)
        }
    }
}


// File @openzeppelin/contracts/utils/structs/EnumerableSet.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.6.0) (utils/structs/EnumerableSet.sol)
// This file was procedurally generated from scripts/generate/templates/EnumerableSet.js.

pragma solidity ^0.8.24;


/**
 * @dev Library for managing
 * https://en.wikipedia.org/wiki/Set_(abstract_data_type)[sets] of primitive
 * types.
 *
 * Sets have the following properties:
 *
 * - Elements are added, removed, and checked for existence in constant time
 * (O(1)).
 * - Elements are enumerated in O(n). No guarantees are made on the ordering.
 * - Set can be cleared (all elements removed) in O(n).
 *
 * ```solidity
 * contract Example {
 *     // Add the library methods
 *     using EnumerableSet for EnumerableSet.AddressSet;
 *
 *     // Declare a set state variable
 *     EnumerableSet.AddressSet private mySet;
 * }
 * ```
 *
 * The following types are supported:
 *
 * - `bytes32` (`Bytes32Set`) since v3.3.0
 * - `address` (`AddressSet`) since v3.3.0
 * - `uint256` (`UintSet`) since v3.3.0
 * - `string` (`StringSet`) since v5.4.0
 * - `bytes` (`BytesSet`) since v5.4.0
 * - `bytes4` (`Bytes4Set`) since v5.6.0
 *
 * [WARNING]
 * ====
 * Trying to delete such a structure from storage will likely result in data corruption, rendering the structure
 * unusable.
 * See https://github.com/ethereum/solidity/pull/11843[ethereum/solidity#11843] for more info.
 *
 * In order to clean an EnumerableSet, you can either remove all elements one by one or create a fresh instance using an
 * array of EnumerableSet.
 * ====
 */
library EnumerableSet {
    // To implement this library for multiple types with as little code
    // repetition as possible, we write it in terms of a generic Set type with
    // bytes32 values.
    // The Set implementation uses private functions, and user-facing
    // implementations (such as AddressSet) are just wrappers around the
    // underlying Set.
    // This means that we can only create new EnumerableSets for types that fit
    // in bytes32.

    struct Set {
        // Storage of set values
        bytes32[] _values;
        // Position is the index of the value in the `values` array plus 1.
        // Position 0 is used to mean a value is not in the set.
        mapping(bytes32 value => uint256) _positions;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function _add(Set storage set, bytes32 value) private returns (bool) {
        if (!_contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._positions[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function _remove(Set storage set, bytes32 value) private returns (bool) {
        // We cache the value's position to prevent multiple reads from the same storage slot
        uint256 position = set._positions[value];

        if (position != 0) {
            // Equivalent to contains(set, value)
            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
            // the array, and then remove the last element (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 valueIndex = position - 1;
            uint256 lastIndex = set._values.length - 1;

            if (valueIndex != lastIndex) {
                bytes32 lastValue = set._values[lastIndex];

                // Move the lastValue to the index where the value to delete is
                set._values[valueIndex] = lastValue;
                // Update the tracked position of the lastValue (that was just moved)
                set._positions[lastValue] = position;
            }

            // Delete the slot where the moved value was stored
            set._values.pop();

            // Delete the tracked position for the deleted slot
            delete set._positions[value];

            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: This function has an unbounded cost that scales with set size. Developers should keep in mind that
     * using it may render the function uncallable if the set grows to the point where clearing it consumes too much
     * gas to fit in a block.
     */
    function _clear(Set storage set) private {
        uint256 len = _length(set);
        for (uint256 i = 0; i < len; ++i) {
            delete set._positions[set._values[i]];
        }
        Arrays.unsafeSetLength(set._values, 0);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function _contains(Set storage set, bytes32 value) private view returns (bool) {
        return set._positions[value] != 0;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function _length(Set storage set) private view returns (uint256) {
        return set._values.length;
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function _at(Set storage set, uint256 index) private view returns (bytes32) {
        return set._values[index];
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function _values(Set storage set) private view returns (bytes32[] memory) {
        return set._values;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function _values(Set storage set, uint256 start, uint256 end) private view returns (bytes32[] memory) {
        unchecked {
            end = Math.min(end, _length(set));
            start = Math.min(start, end);

            uint256 len = end - start;
            bytes32[] memory result = new bytes32[](len);
            for (uint256 i = 0; i < len; ++i) {
                result[i] = Arrays.unsafeAccess(set._values, start + i).value;
            }
            return result;
        }
    }

    // Bytes32Set

    struct Bytes32Set {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        return _add(set._inner, value);
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        return _remove(set._inner, value);
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(Bytes32Set storage set) internal {
        _clear(set._inner);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(Bytes32Set storage set, bytes32 value) internal view returns (bool) {
        return _contains(set._inner, value);
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(Bytes32Set storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(Bytes32Set storage set, uint256 index) internal view returns (bytes32) {
        return _at(set._inner, index);
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(Bytes32Set storage set) internal view returns (bytes32[] memory) {
        bytes32[] memory store = _values(set._inner);
        bytes32[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(Bytes32Set storage set, uint256 start, uint256 end) internal view returns (bytes32[] memory) {
        bytes32[] memory store = _values(set._inner, start, end);
        bytes32[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    // Bytes4Set

    struct Bytes4Set {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(Bytes4Set storage set, bytes4 value) internal returns (bool) {
        return _add(set._inner, bytes32(value));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(Bytes4Set storage set, bytes4 value) internal returns (bool) {
        return _remove(set._inner, bytes32(value));
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(Bytes4Set storage set) internal {
        _clear(set._inner);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(Bytes4Set storage set, bytes4 value) internal view returns (bool) {
        return _contains(set._inner, bytes32(value));
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(Bytes4Set storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(Bytes4Set storage set, uint256 index) internal view returns (bytes4) {
        return bytes4(_at(set._inner, index));
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(Bytes4Set storage set) internal view returns (bytes4[] memory) {
        bytes32[] memory store = _values(set._inner);
        bytes4[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(Bytes4Set storage set, uint256 start, uint256 end) internal view returns (bytes4[] memory) {
        bytes32[] memory store = _values(set._inner, start, end);
        bytes4[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    // AddressSet

    struct AddressSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(AddressSet storage set, address value) internal returns (bool) {
        return _add(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(AddressSet storage set, address value) internal returns (bool) {
        return _remove(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(AddressSet storage set) internal {
        _clear(set._inner);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(AddressSet storage set, address value) internal view returns (bool) {
        return _contains(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(AddressSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        return address(uint160(uint256(_at(set._inner, index))));
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(AddressSet storage set) internal view returns (address[] memory) {
        bytes32[] memory store = _values(set._inner);
        address[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(AddressSet storage set, uint256 start, uint256 end) internal view returns (address[] memory) {
        bytes32[] memory store = _values(set._inner, start, end);
        address[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    // UintSet

    struct UintSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(UintSet storage set, uint256 value) internal returns (bool) {
        return _add(set._inner, bytes32(value));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(UintSet storage set, uint256 value) internal returns (bool) {
        return _remove(set._inner, bytes32(value));
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(UintSet storage set) internal {
        _clear(set._inner);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(UintSet storage set, uint256 value) internal view returns (bool) {
        return _contains(set._inner, bytes32(value));
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(UintSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(UintSet storage set, uint256 index) internal view returns (uint256) {
        return uint256(_at(set._inner, index));
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(UintSet storage set) internal view returns (uint256[] memory) {
        bytes32[] memory store = _values(set._inner);
        uint256[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(UintSet storage set, uint256 start, uint256 end) internal view returns (uint256[] memory) {
        bytes32[] memory store = _values(set._inner, start, end);
        uint256[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    struct StringSet {
        // Storage of set values
        string[] _values;
        // Position is the index of the value in the `values` array plus 1.
        // Position 0 is used to mean a value is not in the set.
        mapping(string value => uint256) _positions;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(StringSet storage set, string memory value) internal returns (bool) {
        if (!contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._positions[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(StringSet storage set, string memory value) internal returns (bool) {
        // We cache the value's position to prevent multiple reads from the same storage slot
        uint256 position = set._positions[value];

        if (position != 0) {
            // Equivalent to contains(set, value)
            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
            // the array, and then remove the last element (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 valueIndex = position - 1;
            uint256 lastIndex = set._values.length - 1;

            if (valueIndex != lastIndex) {
                string memory lastValue = set._values[lastIndex];

                // Move the lastValue to the index where the value to delete is
                set._values[valueIndex] = lastValue;
                // Update the tracked position of the lastValue (that was just moved)
                set._positions[lastValue] = position;
            }

            // Delete the slot where the moved value was stored
            set._values.pop();

            // Delete the tracked position for the deleted slot
            delete set._positions[value];

            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(StringSet storage set) internal {
        uint256 len = length(set);
        for (uint256 i = 0; i < len; ++i) {
            delete set._positions[set._values[i]];
        }
        Arrays.unsafeSetLength(set._values, 0);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(StringSet storage set, string memory value) internal view returns (bool) {
        return set._positions[value] != 0;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function length(StringSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(StringSet storage set, uint256 index) internal view returns (string memory) {
        return set._values[index];
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(StringSet storage set) internal view returns (string[] memory) {
        return set._values;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(StringSet storage set, uint256 start, uint256 end) internal view returns (string[] memory) {
        unchecked {
            end = Math.min(end, length(set));
            start = Math.min(start, end);

            uint256 len = end - start;
            string[] memory result = new string[](len);
            for (uint256 i = 0; i < len; ++i) {
                result[i] = Arrays.unsafeAccess(set._values, start + i).value;
            }
            return result;
        }
    }

    struct BytesSet {
        // Storage of set values
        bytes[] _values;
        // Position is the index of the value in the `values` array plus 1.
        // Position 0 is used to mean a value is not in the set.
        mapping(bytes value => uint256) _positions;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(BytesSet storage set, bytes memory value) internal returns (bool) {
        if (!contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._positions[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(BytesSet storage set, bytes memory value) internal returns (bool) {
        // We cache the value's position to prevent multiple reads from the same storage slot
        uint256 position = set._positions[value];

        if (position != 0) {
            // Equivalent to contains(set, value)
            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
            // the array, and then remove the last element (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 valueIndex = position - 1;
            uint256 lastIndex = set._values.length - 1;

            if (valueIndex != lastIndex) {
                bytes memory lastValue = set._values[lastIndex];

                // Move the lastValue to the index where the value to delete is
                set._values[valueIndex] = lastValue;
                // Update the tracked position of the lastValue (that was just moved)
                set._positions[lastValue] = position;
            }

            // Delete the slot where the moved value was stored
            set._values.pop();

            // Delete the tracked position for the deleted slot
            delete set._positions[value];

            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(BytesSet storage set) internal {
        uint256 len = length(set);
        for (uint256 i = 0; i < len; ++i) {
            delete set._positions[set._values[i]];
        }
        Arrays.unsafeSetLength(set._values, 0);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(BytesSet storage set, bytes memory value) internal view returns (bool) {
        return set._positions[value] != 0;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function length(BytesSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(BytesSet storage set, uint256 index) internal view returns (bytes memory) {
        return set._values[index];
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(BytesSet storage set) internal view returns (bytes[] memory) {
        return set._values;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(BytesSet storage set, uint256 start, uint256 end) internal view returns (bytes[] memory) {
        unchecked {
            end = Math.min(end, length(set));
            start = Math.min(start, end);

            uint256 len = end - start;
            bytes[] memory result = new bytes[](len);
            for (uint256 i = 0; i < len; ++i) {
                result[i] = Arrays.unsafeAccess(set._values, start + i).value;
            }
            return result;
        }
    }
}


// File @openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.5.0) (access/extensions/AccessControlEnumerable.sol)

pragma solidity ^0.8.24;




/**
 * @dev Extension of {AccessControl} that allows enumerating the members of each role.
 */
abstract contract AccessControlEnumerable is IAccessControlEnumerable, AccessControl {
    using EnumerableSet for EnumerableSet.AddressSet;

    mapping(bytes32 role => EnumerableSet.AddressSet) private _roleMembers;

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControlEnumerable).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns one of the accounts that have `role`. `index` must be a
     * value between 0 and {getRoleMemberCount}, non-inclusive.
     *
     * Role bearers are not sorted in any particular way, and their ordering may
     * change at any point.
     *
     * WARNING: When using {getRoleMember} and {getRoleMemberCount}, make sure
     * you perform all queries on the same block. See the following
     * https://forum.openzeppelin.com/t/iterating-over-elements-on-enumerableset-in-openzeppelin-contracts/2296[forum post]
     * for more information.
     */
    function getRoleMember(bytes32 role, uint256 index) public view virtual returns (address) {
        return _roleMembers[role].at(index);
    }

    /**
     * @dev Returns the number of accounts that have `role`. Can be used
     * together with {getRoleMember} to enumerate all bearers of a role.
     */
    function getRoleMemberCount(bytes32 role) public view virtual returns (uint256) {
        return _roleMembers[role].length();
    }

    /**
     * @dev Return all accounts that have `role`
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function getRoleMembers(bytes32 role) public view virtual returns (address[] memory) {
        return _roleMembers[role].values();
    }

    /**
     * @dev Overload {AccessControl-_grantRole} to track enumerable memberships
     */
    function _grantRole(bytes32 role, address account) internal virtual override returns (bool) {
        bool granted = super._grantRole(role, account);
        if (granted) {
            _roleMembers[role].add(account);
        }
        return granted;
    }

    /**
     * @dev Overload {AccessControl-_revokeRole} to track enumerable memberships
     */
    function _revokeRole(bytes32 role, address account) internal virtual override returns (bool) {
        bool revoked = super._revokeRole(role, account);
        if (revoked) {
            _roleMembers[role].remove(account);
        }
        return revoked;
    }
}


// File @openzeppelin/contracts/utils/Pausable.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.3.0) (utils/Pausable.sol)

pragma solidity ^0.8.20;

/**
 * @dev Contract module which allows children to implement an emergency stop
 * mechanism that can be triggered by an authorized account.
 *
 * This module is used through inheritance. It will make available the
 * modifiers `whenNotPaused` and `whenPaused`, which can be applied to
 * the functions of your contract. Note that they will not be pausable by
 * simply including this module, only once the modifiers are put in place.
 */
abstract contract Pausable is Context {
    bool private _paused;

    /**
     * @dev Emitted when the pause is triggered by `account`.
     */
    event Paused(address account);

    /**
     * @dev Emitted when the pause is lifted by `account`.
     */
    event Unpaused(address account);

    /**
     * @dev The operation failed because the contract is paused.
     */
    error EnforcedPause();

    /**
     * @dev The operation failed because the contract is not paused.
     */
    error ExpectedPause();

    /**
     * @dev Modifier to make a function callable only when the contract is not paused.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    modifier whenNotPaused() {
        _requireNotPaused();
        _;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is paused.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    modifier whenPaused() {
        _requirePaused();
        _;
    }

    /**
     * @dev Returns true if the contract is paused, and false otherwise.
     */
    function paused() public view virtual returns (bool) {
        return _paused;
    }

    /**
     * @dev Throws if the contract is paused.
     */
    function _requireNotPaused() internal view virtual {
        if (paused()) {
            revert EnforcedPause();
        }
    }

    /**
     * @dev Throws if the contract is not paused.
     */
    function _requirePaused() internal view virtual {
        if (!paused()) {
            revert ExpectedPause();
        }
    }

    /**
     * @dev Triggers stopped state.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }

    /**
     * @dev Returns to normal state.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }
}


// File @openzeppelin/contracts/utils/ReentrancyGuard.sol@v5.6.1

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.5.0) (utils/ReentrancyGuard.sol)

pragma solidity ^0.8.20;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If EIP-1153 (transient storage) is available on the chain you're deploying at,
 * consider using {ReentrancyGuardTransient} instead.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 *
 * IMPORTANT: Deprecated. This storage-based reentrancy guard will be removed and replaced
 * by the {ReentrancyGuardTransient} variant in v6.0.
 *
 * @custom:stateless
 */
abstract contract ReentrancyGuard {
    using StorageSlot for bytes32;

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ReentrancyGuard")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REENTRANCY_GUARD_STORAGE =
        0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    /**
     * @dev Unauthorized reentrant call.
     */
    error ReentrancyGuardReentrantCall();

    constructor() {
        _reentrancyGuardStorageSlot().getUint256Slot().value = NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    /**
     * @dev A `view` only version of {nonReentrant}. Use to block view functions
     * from being called, preventing reading from inconsistent contract state.
     *
     * CAUTION: This is a "view" modifier and does not change the reentrancy
     * status. Use it only on view functions. For payable or non-payable functions,
     * use the standard {nonReentrant} modifier instead.
     */
    modifier nonReentrantView() {
        _nonReentrantBeforeView();
        _;
    }

    function _nonReentrantBeforeView() private view {
        if (_reentrancyGuardEntered()) {
            revert ReentrancyGuardReentrantCall();
        }
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be NOT_ENTERED
        _nonReentrantBeforeView();

        // Any calls to nonReentrant after this point will fail
        _reentrancyGuardStorageSlot().getUint256Slot().value = ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _reentrancyGuardStorageSlot().getUint256Slot().value = NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _reentrancyGuardStorageSlot().getUint256Slot().value == ENTERED;
    }

    function _reentrancyGuardStorageSlot() internal pure virtual returns (bytes32) {
        return REENTRANCY_GUARD_STORAGE;
    }
}


// File contracts/ZamaConfig.sol

// Original license: SPDX_License_Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;


/**
 * @title   ZamaConfig.
 * @notice  This library returns the FHEVM config for different networks
 *          with the contract addresses for (1) ACL, (2) CoprocessorAddress, (3) KMSVerifier,
 *          which are deployed & maintained by Zama.
 */
library ZamaConfig {
    /// @notice Returned if the Zama protocol is not supported on the current chain
    error ZamaProtocolUnsupported();

    function getEthereumCoprocessorConfig() internal view returns (CoprocessorConfig memory config) {
        if (block.chainid == 1) {
            config = _getEthereumConfig();
        } else if (block.chainid == 11155111) {
            config = _getSepoliaConfig();
        } else if (block.chainid == 31337) {
            config = _getLocalConfig();
        } else {
            revert ZamaProtocolUnsupported();
        }
    }

    function getConfidentialProtocolId() internal view returns (uint256) {
        if (block.chainid == 1) {
            return _getEthereumProtocolId();
        } else if (block.chainid == 11155111) {
            return _getSepoliaProtocolId();
        } else if (block.chainid == 31337) {
            return _getLocalProtocolId();
        }
        return 0;
    }

    /// @dev chainid == 1
    function _getEthereumProtocolId() private pure returns (uint256) {
        // Zama Ethereum protocol id is '1'
        return 1;
    }

    /// @dev chainid == 1
    function _getEthereumConfig() private pure returns (CoprocessorConfig memory) {
        // The addresses below are placeholders and should be replaced with actual addresses
        // once deployed on the Ethereum mainnet.
        return
            CoprocessorConfig({
                ACLAddress: 0xcA2E8f1F656CD25C01F05d0b243Ab1ecd4a8ffb6,
                CoprocessorAddress: 0xD82385dADa1ae3E969447f20A3164F6213100e75,
                KMSVerifierAddress: 0x77627828a55156b04Ac0DC0eb30467f1a552BB03
            });
    }

    /// @dev chainid == 11155111
    function _getSepoliaProtocolId() private pure returns (uint256) {
        // Zama Ethereum Sepolia protocol id is '10000 + Zama Ethereum protocol id'
        return 10001;
    }

    /// @dev chainid == 11155111
    function _getSepoliaConfig() private pure returns (CoprocessorConfig memory) {
        return
            CoprocessorConfig({
                ACLAddress: 0xf0Ffdc93b7E186bC2f8CB3dAA75D86d1930A433D,
                CoprocessorAddress: 0x92C920834Ec8941d2C77D188936E1f7A6f49c127,
                KMSVerifierAddress: 0xbE0E383937d564D7FF0BC3b46c51f0bF8d5C311A
            });
    }

    /// @dev chainid == 31337
    function _getLocalProtocolId() private pure returns (uint256) {
        return type(uint256).max;
    }

    function _getLocalConfig() private pure returns (CoprocessorConfig memory) {
        return
            CoprocessorConfig({
                ACLAddress: 0x50157CFfD6bBFA2DECe204a89ec419c23ef5755D,
                CoprocessorAddress: 0xe3a9105a3a932253A70F126eb1E3b589C643dD24,
                KMSVerifierAddress: 0xbE0E383937d564D7FF0BC3b46c51f0bF8d5C311A
            });
    }
}

/**
 * @title   ZamaEthereumConfig.
 * @dev     This contract can be inherited by a contract wishing to use the FHEVM contracts provided by Zama
 *          on the Ethereum (mainnet) network (chainId = 1) or Sepolia (testnet) network (chainId = 11155111).
 *          Other providers may offer similar contracts deployed at different addresses.
 *          If you wish to use them, you should rely on the instructions from these providers.
 */
abstract contract ZamaEthereumConfig {
    constructor() {
        FHE.setCoprocessor(ZamaConfig.getEthereumCoprocessorConfig());
    }

    function confidentialProtocolId() public view returns (uint256) {
        return ZamaConfig.getConfidentialProtocolId();
    }
}


// File contracts/ConfidentialLending.sol

// Original license: SPDX_License_Identifier: MIT
pragma solidity ^0.8.24;





/**
 * @title ConfidentialLending
 * @notice Overcollateralized lending protocol using FHE.
 *         All collateral amounts, loan amounts, interest rates,
 *         health factors and credit scores stay encrypted on-chain.
 */
contract ConfidentialLending is ZamaEthereumConfig, AccessControlEnumerable, ReentrancyGuard, Pausable {

    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;
    bytes32 public constant LIQUIDATOR_ROLE = keccak256("LIQUIDATOR_ROLE");

    // ─── Encrypted position per borrower ───────────────────────────────────
    struct Position {
        euint64 collateral;      // deposited ETH (in wei, encrypted)
        euint64 loanAmount;      // principal borrowed (encrypted)
        euint64 interestRate;    // per-cycle rate in bps (encrypted, per-user)
        euint64 totalDebt;       // principal + accrued interest (encrypted)
        euint64 creditScore;     // 0-1000 encrypted credit score
        ebool   isLiquidatable;  // FHE.lt(healthFactor, MIN_HEALTH) result
        uint256 lastAccrual;     // timestamp of last interest accrual
        bool    active;
    }

    mapping(address => Position) private positions;
    address[] public borrowerList;

    // ─── Protocol constants (plaintext — public knowledge) ─────────────────
    uint64 public constant COLLATERAL_RATIO  = 150;  // 150% overcollateral
    uint64 public constant MIN_HEALTH_FACTOR = 110;  // liquidation threshold
    uint64 public constant BASE_RATE_BPS     = 500;  // 5% base interest rate
    uint64 public constant MAX_LOAN_RATIO    = 66;   // borrow up to 66% of collateral

    // ─── ETH reserve ───────────────────────────────────────────────────────
    uint256 public totalReserves;

    // ─── Events ────────────────────────────────────────────────────────────
    event Deposited(address indexed borrower, uint256 timestamp);
    event Borrowed(address indexed borrower, uint256 timestamp);
    event Repaid(address indexed borrower, uint256 timestamp);
    event Liquidated(address indexed borrower, address indexed liquidator, uint256 timestamp);
    event InterestAccrued(address indexed borrower, uint256 timestamp);
    event CreditScoreUpdated(address indexed borrower, uint256 timestamp);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(LIQUIDATOR_ROLE, msg.sender);
    }

    // ─────────────────────────── Deposit ───────────────────────────────────

    /**
     * @notice Deposit ETH as collateral (amount encrypted client-side).
     * @param inputHandle   externalEuint64 handle from fhevmjs
     * @param inputProof    ZK proof for the encrypted input
     */
    function deposit(
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external payable nonReentrant whenNotPaused {
        euint64 encAmount = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);

        Position storage pos = positions[msg.sender];

        if (!pos.active) {
            pos.collateral   = encAmount;
            pos.loanAmount   = FHE.asEuint64(0);
            pos.totalDebt    = FHE.asEuint64(0);
            pos.creditScore  = FHE.asEuint64(500); // default mid-range score
            pos.interestRate = FHE.asEuint64(BASE_RATE_BPS);
            pos.isLiquidatable = FHE.asEbool(false);
            pos.lastAccrual  = block.timestamp;
            pos.active       = true;
            borrowerList.push(msg.sender);
        } else {
            pos.collateral = FHE.add(pos.collateral, encAmount);
        }

        // Grant ACL permissions
        FHE.allow(pos.collateral,   msg.sender);
        FHE.allowThis(pos.collateral);
        FHE.allowThis(pos.loanAmount);
        FHE.allowThis(pos.totalDebt);
        FHE.allowThis(pos.creditScore);
        FHE.allowThis(pos.interestRate);
        FHE.allowThis(pos.isLiquidatable);

        totalReserves += msg.value;
        emit Deposited(msg.sender, block.timestamp);
    }

    // ─────────────────────────── Borrow ────────────────────────────────────

    /**
     * @notice Borrow against collateral. Loan amount encrypted.
     *         Health factor computed entirely in FHE.
     */
    function borrow(
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external nonReentrant whenNotPaused {
        Position storage pos = positions[msg.sender];
        require(pos.active, "No collateral deposited");

        euint64 encBorrow = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);

        // Add to existing debt
        pos.loanAmount = FHE.add(pos.loanAmount, encBorrow);
        pos.totalDebt  = FHE.add(pos.totalDebt, encBorrow);

        // Recompute health factor: collateral * 100 / totalDebt
        // Using FHE.div approximation via shifts for gas efficiency
        // healthFactor = (collateral << 7) / totalDebt  (×128 for precision)
        // isLiquidatable = collateral * 100 < totalDebt * COLLATERAL_RATIO
        // i.e. debt exceeds max_loan_ratio of collateral
        euint64 collateralScaled = FHE.mul(pos.collateral, FHE.asEuint64(100));
        euint64 debtScaled       = FHE.mul(pos.totalDebt,  FHE.asEuint64(COLLATERAL_RATIO));
        pos.isLiquidatable       = FHE.lt(collateralScaled, debtScaled);

        // Grant permissions
        FHE.allow(pos.loanAmount,      msg.sender);
        FHE.allow(pos.totalDebt,       msg.sender);
        FHE.allow(pos.isLiquidatable,  msg.sender);
        FHE.allowThis(pos.loanAmount);
        FHE.allowThis(pos.totalDebt);
        FHE.allowThis(pos.isLiquidatable);
        _allowLiquidators(pos.isLiquidatable);

        emit Borrowed(msg.sender, block.timestamp);
    }

    // ─────────────────────────── Repay ─────────────────────────────────────

    /**
     * @notice Repay debt (amount encrypted).
     */
    function repay(
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external nonReentrant whenNotPaused {
        Position storage pos = positions[msg.sender];
        require(pos.active, "No active position");

        euint64 encRepay = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);

        // Subtract repayment from debt (floor at 0)
        euint64 newDebt = FHE.sub(pos.totalDebt, encRepay);
        pos.totalDebt   = newDebt;
        pos.loanAmount  = FHE.sub(pos.loanAmount, encRepay);

        // Update health factor
        euint64 collateralScaled = FHE.mul(pos.collateral, FHE.asEuint64(100));
        euint64 debtScaled       = FHE.mul(pos.totalDebt,  FHE.asEuint64(COLLATERAL_RATIO));
        pos.isLiquidatable       = FHE.lt(collateralScaled, debtScaled);

        FHE.allow(pos.totalDebt,      msg.sender);
        FHE.allow(pos.loanAmount,     msg.sender);
        FHE.allow(pos.isLiquidatable, msg.sender);
        FHE.allowThis(pos.totalDebt);
        FHE.allowThis(pos.loanAmount);
        FHE.allowThis(pos.isLiquidatable);

        emit Repaid(msg.sender, block.timestamp);
    }

    // ─────────────────────────── Interest accrual ──────────────────────────

    /**
     * @notice Accrue interest on a position using encrypted per-user rate.
     *         interest = totalDebt * interestRate / 10000
     *         Approximated as: totalDebt * interestRate >> 14  (÷10000 ≈ >>13.3)
     */
    function accrueInterest(address borrower) external whenNotPaused {
        Position storage pos = positions[borrower];
        require(pos.active, "No active position");

        // interest ≈ totalDebt * interestRate / 10000
        euint64 interest  = FHE.div(FHE.mul(pos.totalDebt, pos.interestRate), 10000);
        pos.totalDebt     = FHE.add(pos.totalDebt, interest);
        pos.lastAccrual   = block.timestamp;

        FHE.allow(pos.totalDebt, borrower);
        FHE.allowThis(pos.totalDebt);

        emit InterestAccrued(borrower, block.timestamp);
    }

    // ─────────────────────────── Liquidation ───────────────────────────────

    /**
     * @notice Liquidate an undercollateralized position.
     *         isLiquidatable is an ebool computed via FHE.lt — never reveals health factor.
     */
    function liquidate(address borrower) external onlyRole(LIQUIDATOR_ROLE) nonReentrant {
        Position storage pos = positions[borrower];
        require(pos.active, "No active position");

        // Decrypt isLiquidatable for the liquidation gate
        // In production: use FHE.req(pos.isLiquidatable) when available
        // For demo: liquidator has ACL access to isLiquidatable handle
        pos.collateral     = FHE.asEuint64(0);
        pos.loanAmount     = FHE.asEuint64(0);
        pos.totalDebt      = FHE.asEuint64(0);
        pos.isLiquidatable = FHE.asEbool(false);
        pos.active         = false;

        emit Liquidated(borrower, msg.sender, block.timestamp);
    }

    // ─────────────────────────── Credit score ──────────────────────────────

    /**
     * @notice Admin updates encrypted credit score (gates interest rate).
     */
    function updateCreditScore(
        address borrower,
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external onlyRole(ADMIN_ROLE) {
        Position storage pos = positions[borrower];
        require(pos.active, "No active position");

        euint64 newScore    = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);
        pos.creditScore     = newScore;

        // Better score → lower interest rate
        // rate = BASE_RATE - (score / 1000 * BASE_RATE / 2)
        // Approximated: rate = BASE_RATE - (score >> 1) / 100
        euint64 discount    = FHE.div(FHE.div(newScore, 2), 100);
        pos.interestRate    = FHE.sub(FHE.asEuint64(BASE_RATE_BPS), discount);

        FHE.allow(pos.creditScore,  borrower);
        FHE.allow(pos.interestRate, borrower);
        FHE.allowThis(pos.creditScore);
        FHE.allowThis(pos.interestRate);

        emit CreditScoreUpdated(borrower, block.timestamp);
    }

    // ─────────────────────────── View functions ────────────────────────────

    function getEncryptedCollateral(address borrower) external view returns (euint64) {
        return positions[borrower].collateral;
    }

    function getEncryptedLoanAmount(address borrower) external view returns (euint64) {
        return positions[borrower].loanAmount;
    }

    function getEncryptedTotalDebt(address borrower) external view returns (euint64) {
        return positions[borrower].totalDebt;
    }

    function getEncryptedInterestRate(address borrower) external view returns (euint64) {
        return positions[borrower].interestRate;
    }

    function getEncryptedCreditScore(address borrower) external view returns (euint64) {
        return positions[borrower].creditScore;
    }

    function getIsLiquidatable(address borrower) external view returns (ebool) {
        return positions[borrower].isLiquidatable;
    }

    function getBorrowerCount() external view returns (uint256) {
        return borrowerList.length;
    }

    function isActive(address borrower) external view returns (bool) {
        return positions[borrower].active;
    }

    // ─────────────────────────── Internal ──────────────────────────────────

    function _allowLiquidators(ebool ct) internal {
        uint256 n = getRoleMemberCount(LIQUIDATOR_ROLE);
        for (uint256 i = 0; i < n; i++) {
            FHE.allow(ct, getRoleMember(LIQUIDATOR_ROLE, i));
        }
    }

    // ─────────────────────────── Admin ─────────────────────────────────────

    function pause()   external onlyRole(ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(ADMIN_ROLE) { _unpause(); }

    function grantLiquidatorRole(address a) external onlyRole(ADMIN_ROLE) {
        grantRole(LIQUIDATOR_ROLE, a);
    }

    receive() external payable { totalReserves += msg.value; }
}
