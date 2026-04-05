// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {euint64, ebool} from "@fhevm/solidity/lib/FHE.sol";

/**
 * @title IConfidentialCreditScore
 * @notice Interface for the ShieldScore credit scoring module.
 *         ShieldLend imports this to gate loan terms.
 *         Extractable: copy IConfidentialCreditScore.sol + ConfidentialCreditScore.sol to any project.
 */
interface IConfidentialCreditScore {
    /**
     * @notice Returns encrypted credit score for an address.
     *         ACL-gated: only the subject and ORACLE_ROLE can re-encrypt it.
     */
    function getEncryptedScore(address subject) external view returns (euint64);

    /**
     * @notice Returns encrypted ebool: score >= threshold.
     *         Used by ShieldLend to gate loan tiers without revealing the score.
     * @param subject   Borrower address
     * @param threshold Plaintext score threshold (e.g. 600, 750, 900)
     */
    function meetsThreshold(address subject, uint64 threshold) external returns (ebool);

    /**
     * @notice Returns true if subject has an active score record.
     */
    function hasScore(address subject) external view returns (bool);

    // ─── Events ────────────────────────────────────────────────────────────
    event ScoreSet(address indexed subject, uint256 timestamp);
    event ThresholdChecked(address indexed subject, uint64 threshold, bytes32 resultHandle);
    event DisputeOpened(address indexed subject, uint256 timestamp);
    event DisputeVoteCast(address indexed subject, address indexed reviewer, uint256 timestamp);
    event DisputeResolved(address indexed subject, bool approved, uint256 timestamp);
    event ScoreRevealRequested(address indexed subject, bytes32 handle, uint256 timestamp);
    event ScoreRevealed(address indexed subject, uint64 score, uint256 timestamp);
}
