// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";
import {IOracle} from "./IOracle.sol";

/**
 * @title ChainlinkOracle
 * @notice Standalone oracle adapter that converts Chainlink price feeds to
 *         ETH-wei-per-token values consumed by ConfidentialLending.
 *
 * Supports two feed types:
 *   - Token/ETH directly  (isUsdFeed = false)
 *   - Token/USD + ETH/USD (isUsdFeed = true)  → divides to get Token/ETH
 *
 * Admin can register feeds per token and set fallback prices for tokens
 * that have no Chainlink feed on the current network (e.g. Sepolia test tokens).
 *
 * Sepolia ETH/USD: 0x694AA1769357215DE4FAC081bf1f309aDC325306
 */
contract ChainlinkOracle is IOracle, Ownable {

    // ─── State ─────────────────────────────────────────────────────────────

    /// @notice Chainlink aggregator per token (address(0) = use fallback).
    mapping(address => address) public aggregators;

    /// @notice If true, the feed returns Token/USD and needs ETH/USD conversion.
    mapping(address => bool) public isUsdFeed;

    /// @notice ETH/USD aggregator address (used when isUsdFeed[token] == true).
    address public ethUsdAggregator;

    /// @notice Admin-set fallback price (ETH-wei per whole token) for tokens
    ///         without a Chainlink feed. 0 = no fallback.
    mapping(address => uint256) public fallbackPrices;

    /// @notice Seconds before a price is considered stale. Default: 1 hour.
    uint256 public maxStaleness = 3600;

    // ─── Events ────────────────────────────────────────────────────────────

    event FeedAdded(address indexed token, address indexed aggregator, bool isUsd);
    event FallbackPriceSet(address indexed token, uint256 ethWeiPerToken);
    event EthUsdAggregatorSet(address indexed aggregator);
    event MaxStalenessUpdated(uint256 seconds_);

    // ─── Constructor ───────────────────────────────────────────────────────

    constructor(address _ethUsdAggregator) Ownable(msg.sender) {
        ethUsdAggregator = _ethUsdAggregator;
    }

    // ─── Admin ─────────────────────────────────────────────────────────────

    /// @notice Register a Chainlink price feed for a token.
    /// @param token       ERC20 token address (or address(0) for ETH itself)
    /// @param aggregator  Chainlink AggregatorV3Interface address
    /// @param _isUsdFeed  true if feed is Token/USD (requires ethUsdAggregator to be set)
    function addFeed(address token, address aggregator, bool _isUsdFeed) external onlyOwner {
        require(aggregator != address(0), "Zero aggregator");
        if (_isUsdFeed) require(ethUsdAggregator != address(0), "ETH/USD aggregator not set");
        aggregators[token] = aggregator;
        isUsdFeed[token]   = _isUsdFeed;
        emit FeedAdded(token, aggregator, _isUsdFeed);
    }

    /// @notice Set admin fallback price for a token without a Chainlink feed.
    /// @param token           ERC20 token address
    /// @param ethWeiPerToken  ETH-wei value of 1 whole token (18-decimal normalised)
    function setFallbackPrice(address token, uint256 ethWeiPerToken) external onlyOwner {
        require(ethWeiPerToken > 0, "Zero price");
        fallbackPrices[token] = ethWeiPerToken;
        emit FallbackPriceSet(token, ethWeiPerToken);
    }

    /// @notice Update the ETH/USD aggregator address.
    function setEthUsdAggregator(address aggregator) external onlyOwner {
        require(aggregator != address(0), "Zero address");
        ethUsdAggregator = aggregator;
        emit EthUsdAggregatorSet(aggregator);
    }

    /// @notice Update the staleness threshold (in seconds).
    function setMaxStaleness(uint256 seconds_) external onlyOwner {
        require(seconds_ >= 60, "Too short");
        maxStaleness = seconds_;
        emit MaxStalenessUpdated(seconds_);
    }

    // ─── IOracle ──────────────────────────────────────────────────────────

    /**
     * @notice Returns ETH-wei value of 1 whole token.
     *
     * Resolution order:
     *   1. If token has a Chainlink aggregator, fetch latestRoundData.
     *      - isUsdFeed=false: price already in ETH, scale to 18 decimals.
     *      - isUsdFeed=true:  tokenUsdPrice / ethUsdPrice, scaled to 18 decimals.
     *   2. Else use fallbackPrices[token].
     *   3. Revert if neither is available or price is stale / ≤ 0.
     */
    function getEthWeiPerToken(address token) external view override returns (uint256) {
        address agg = aggregators[token];

        if (agg != address(0)) {
            (, int256 price,, uint256 updatedAt,) = AggregatorV3Interface(agg).latestRoundData();
            require(price > 0, "Oracle: invalid price");
            require(block.timestamp - updatedAt <= maxStaleness, "Oracle: stale price");

            uint8 decimals = AggregatorV3Interface(agg).decimals();

            if (isUsdFeed[token]) {
                // Token/USD — divide by ETH/USD to get Token/ETH
                (, int256 ethUsdPrice,, uint256 ethUpdatedAt,) =
                    AggregatorV3Interface(ethUsdAggregator).latestRoundData();
                require(ethUsdPrice > 0, "Oracle: invalid ETH/USD price");
                require(block.timestamp - ethUpdatedAt <= maxStaleness, "Oracle: stale ETH/USD");

                uint8 ethDecimals = AggregatorV3Interface(ethUsdAggregator).decimals();

                // ethWeiPerToken = (tokenUsdPrice * 1e18 * 10^ethDecimals) / (ethUsdPrice * 10^decimals)
                // Both feeds typically use 8 decimals, so ethDecimals == decimals → simplifies to:
                // ethWeiPerToken = tokenUsdPrice * 1e18 / ethUsdPrice
                return (uint256(price) * 1e18 * (10 ** ethDecimals)) /
                       (uint256(ethUsdPrice) * (10 ** decimals));
            } else {
                // Token/ETH — scale to 18 decimals
                // ethWeiPerToken = price * 1e18 / 10^decimals
                return (uint256(price) * 1e18) / (10 ** decimals);
            }
        }

        // Fallback
        uint256 fb = fallbackPrices[token];
        require(fb > 0, "Oracle: no price source");
        return fb;
    }

    /**
     * @notice Returns true if the feed for token is older than maxStaleness.
     *         Returns false (not stale) if no aggregator and fallback is set.
     */
    function isStale(address token) external view override returns (bool) {
        address agg = aggregators[token];
        if (agg == address(0)) return false; // fallback is always "fresh"
        (,,,uint256 updatedAt,) = AggregatorV3Interface(agg).latestRoundData();
        return block.timestamp - updatedAt > maxStaleness;
    }
}
