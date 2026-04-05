// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FHE, euint64, euint8, ebool, externalEuint64, externalEuint8} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "../ZamaConfig.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {IConfidentialCreditScore} from "./IConfidentialCreditScore.sol";

/**
 * @title ConfidentialCreditScore (ShieldScore module)
 * @notice Privacy-preserving credit scoring protocol built on Zama fhEVM.
 *
 * Architecture
 * ------------
 *  ORACLE_ROLE   — sets encrypted scores (off-chain model submits result)
 *  REVIEWER_ROLE — casts encrypted dispute votes (0=deny, 1=approve)
 *  Subject       — the wallet being scored; can re-encrypt own score, open disputes
 *
 * Key FHE patterns used
 * ---------------------
 *  - euint64 score storage + ACL grants (subject + oracle read)
 *  - FHE.select for threshold comparison without revealing score
 *  - euint8 encrypted dispute votes — tallied via FHE.add
 *  - FHE.makePubliclyDecryptable + FHE.checkSignatures for public dispute reveal
 *
 * Extractable
 * -----------
 *  This contract + IConfidentialCreditScore.sol are self-contained.
 *  To use standalone: deploy separately, grant ORACLE_ROLE to your off-chain scorer,
 *  then call meetsThreshold() from any other contract.
 */
contract ConfidentialCreditScore is ZamaEthereumConfig, AccessControlEnumerable, IConfidentialCreditScore {

    bytes32 public constant ORACLE_ROLE   = keccak256("ORACLE_ROLE");
    bytes32 public constant REVIEWER_ROLE = keccak256("REVIEWER_ROLE");

    // ─── Score storage ──────────────────────────────────────────────────────
    struct ScoreRecord {
        euint64 score;          // 0-1000, encrypted
        uint256 updatedAt;
        bool    active;
    }
    mapping(address => ScoreRecord) private scores;

    // ─── Dispute system ─────────────────────────────────────────────────────
    struct Dispute {
        euint64 yesVotes;       // encrypted tally of approval votes
        euint64 noVotes;        // encrypted tally of denial votes
        uint256 openedAt;
        uint256 deadline;       // voting closes at this timestamp
        bool    resolved;
        bool    active;
    }
    mapping(address => Dispute)                   private disputes;
    mapping(address => mapping(address => bool))  private hasVoted;    // subject => reviewer => voted

    // ─── Score reveal (public decryption) ───────────────────────────────────
    mapping(address => bool) private pendingReveal;

    // ─── Config ─────────────────────────────────────────────────────────────
    uint256 public constant DISPUTE_DURATION = 3 days;
    uint64  public constant DEFAULT_SCORE    = 500;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ORACLE_ROLE, msg.sender);
        _grantRole(REVIEWER_ROLE, msg.sender);
    }

    // ─────────────────────────── Oracle: set score ──────────────────────────

    /**
     * @notice Oracle submits an encrypted credit score for a subject.
     * @param subject       Wallet being scored
     * @param inputHandle   externalEuint64 handle (fhevmjs.encryptUint)
     * @param inputProof    ZK proof from fhevmjs
     */
    function setScore(
        address subject,
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external onlyRole(ORACLE_ROLE) {
        euint64 newScore = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);

        // Subject can re-encrypt their own score
        FHE.allow(newScore, subject);
        // Oracle and contract can operate on it
        FHE.allow(newScore, msg.sender);
        FHE.allowThis(newScore);

        scores[subject] = ScoreRecord({ score: newScore, updatedAt: block.timestamp, active: true });
        emit ScoreSet(subject, block.timestamp);
    }

    // ─────────────────────────── Read: score access ─────────────────────────

    /**
     * @notice Returns encrypted score handle. ACL-gated — only subject + oracle can decrypt.
     */
    function getEncryptedScore(address subject) external view override returns (euint64) {
        require(scores[subject].active, "No score record");
        return scores[subject].score;
    }

    /**
     * @notice FHE comparison: returns ebool = (score >= threshold).
     *         The score is never revealed — only the comparison result is exposed.
     *         Called by ShieldLend to gate loan tiers without knowing the score.
     * @param subject   Borrower address
     * @param threshold Plaintext threshold (e.g. 600 for standard, 800 for premium)
     */
    function meetsThreshold(address subject, uint64 threshold) external override returns (ebool) {
        require(scores[subject].active, "No score record");
        // not(lt(score, threshold)) = score >= threshold
        ebool result = FHE.not(FHE.lt(scores[subject].score, FHE.asEuint64(threshold)));
        // Grant caller (e.g. ShieldLend contract, or subject in tests) access
        FHE.allow(result, msg.sender);
        FHE.allowThis(result);
        // Emit handle so caller can retrieve it from the receipt
        emit ThresholdChecked(subject, threshold, FHE.toBytes32(result));
        return result;
    }

    function hasScore(address subject) external view override returns (bool) {
        return scores[subject].active;
    }

    // ─────────────────────────── Dispute system ─────────────────────────────

    /**
     * @notice Subject opens a dispute against their current score.
     *         Reviewers have DISPUTE_DURATION to cast encrypted votes.
     */
    function openDispute(address subject) external {
        require(msg.sender == subject, "Only subject can open dispute");
        require(scores[subject].active, "No score to dispute");
        require(!disputes[subject].active, "Dispute already active");

        disputes[subject] = Dispute({
            yesVotes:  FHE.asEuint64(0),
            noVotes:   FHE.asEuint64(0),
            openedAt:  block.timestamp,
            deadline:  block.timestamp + DISPUTE_DURATION,
            resolved:  false,
            active:    true
        });

        FHE.allowThis(disputes[subject].yesVotes);
        FHE.allowThis(disputes[subject].noVotes);

        emit DisputeOpened(subject, block.timestamp);
    }

    /**
     * @notice Reviewer casts an encrypted vote on a dispute.
     *         voteHandle = externalEuint8 where 0=deny, 1=approve
     */
    function castDisputeVote(
        address subject,
        bytes32 voteHandle,
        bytes calldata inputProof
    ) external onlyRole(REVIEWER_ROLE) {
        Dispute storage d = disputes[subject];
        require(d.active && !d.resolved, "No active dispute");
        require(block.timestamp <= d.deadline, "Voting period ended");
        require(!hasVoted[subject][msg.sender], "Already voted");

        euint8 encVote  = FHE.fromExternal(externalEuint8.wrap(voteHandle), inputProof);
        euint64 weight  = FHE.asEuint64(1);
        euint64 zero    = FHE.asEuint64(0);
        euint64 voteU64 = FHE.asEuint64(encVote);  // 0 or 1 → 64-bit

        // Route vote via FHE.select — never reveals which way reviewer voted
        ebool isApprove = FHE.not(FHE.lt(voteU64, FHE.asEuint64(1))); // voteU64 >= 1

        euint64 newYes = FHE.add(d.yesVotes, FHE.select(isApprove, weight, zero));
        euint64 newNo  = FHE.add(d.noVotes,  FHE.select(isApprove, zero,   weight));

        FHE.allowThis(newYes);
        FHE.allowThis(newNo);
        d.yesVotes = newYes;
        d.noVotes  = newNo;

        hasVoted[subject][msg.sender] = true;
        emit DisputeVoteCast(subject, msg.sender, block.timestamp);
    }

    /**
     * @notice Step 1: request public decryption of dispute vote tally after deadline.
     *         Emits handle for Zama relayer to pick up and decrypt.
     */
    function requestDisputeResolve(address subject) external {
        Dispute storage d = disputes[subject];
        require(d.active && !d.resolved, "No active dispute");
        require(block.timestamp > d.deadline, "Voting still open");
        require(!pendingReveal[subject], "Reveal already pending");

        // Make both tallies publicly decryptable
        FHE.makePubliclyDecryptable(d.yesVotes);
        FHE.makePubliclyDecryptable(d.noVotes);
        pendingReveal[subject] = true;

        emit ScoreRevealRequested(subject, FHE.toBytes32(d.yesVotes), block.timestamp);
    }

    /**
     * @notice Step 2: relayer submits decrypted vote tallies + proof.
     *         If yesVotes > noVotes: sets score to DEFAULT_SCORE (score reset / appeal granted).
     *         If noVotes >= yesVotes: dispute rejected.
     */
    function verifyDisputeResolve(
        address subject,
        bytes32[] calldata handlesList,
        bytes calldata abiEncodedCleartexts,
        bytes calldata decryptionProof
    ) external {
        Dispute storage d = disputes[subject];
        require(d.active && !d.resolved, "No active dispute");
        require(pendingReveal[subject], "No pending reveal");

        FHE.checkSignatures(handlesList, abiEncodedCleartexts, decryptionProof);
        (uint64 yesCount, uint64 noCount) = abi.decode(abiEncodedCleartexts, (uint64, uint64));

        bool approved = yesCount > noCount;
        d.resolved  = true;
        d.active    = false;
        delete pendingReveal[subject];

        if (approved) {
            // Reset to neutral default score as relief
            euint64 relief = FHE.asEuint64(DEFAULT_SCORE);
            FHE.allow(relief, subject);
            FHE.allowThis(relief);
            scores[subject].score     = relief;
            scores[subject].updatedAt = block.timestamp;
        }

        emit DisputeResolved(subject, approved, block.timestamp);
    }

    // ─────────────────────────── Score public reveal ─────────────────────────

    /**
     * @notice Subject requests their score to be publicly revealed (e.g. for credit report).
     *         Only the subject can initiate — this is a voluntary disclosure.
     */
    function requestScoreReveal(address subject) external {
        require(msg.sender == subject, "Only subject can reveal their score");
        require(scores[subject].active, "No score record");
        require(!pendingReveal[subject], "Reveal already pending");

        FHE.makePubliclyDecryptable(scores[subject].score);
        pendingReveal[subject] = true;
        emit ScoreRevealRequested(subject, FHE.toBytes32(scores[subject].score), block.timestamp);
    }

    /**
     * @notice Relayer submits decrypted score + proof for public voluntary disclosure.
     */
    function verifyScoreReveal(
        address subject,
        bytes32[] calldata handlesList,
        bytes calldata abiEncodedCleartexts,
        bytes calldata decryptionProof
    ) external {
        require(pendingReveal[subject], "No pending reveal");
        FHE.checkSignatures(handlesList, abiEncodedCleartexts, decryptionProof);
        uint64 scoreValue = abi.decode(abiEncodedCleartexts, (uint64));
        delete pendingReveal[subject];
        emit ScoreRevealed(subject, scoreValue, block.timestamp);
    }

    // ─────────────────────────── View helpers ───────────────────────────────

    function isDisputeActive(address subject) external view returns (bool) {
        return disputes[subject].active && !disputes[subject].resolved;
    }

    function disputeDeadline(address subject) external view returns (uint256) {
        return disputes[subject].deadline;
    }

    function isPendingReveal(address subject) external view returns (bool) {
        return pendingReveal[subject];
    }

    function scoreUpdatedAt(address subject) external view returns (uint256) {
        return scores[subject].updatedAt;
    }

    // ─────────────────────────── Admin ──────────────────────────────────────

    function grantOracleRole(address a)   external onlyRole(DEFAULT_ADMIN_ROLE) { grantRole(ORACLE_ROLE, a); }
    function grantReviewerRole(address a) external onlyRole(DEFAULT_ADMIN_ROLE) { grantRole(REVIEWER_ROLE, a); }
}
