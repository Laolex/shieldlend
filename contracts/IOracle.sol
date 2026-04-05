// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IOracle {
    /// @notice Returns the ETH-wei value of 1 whole token (18-decimal normalised).
    ///         e.g. USDC at 3000 USDC/ETH → 1e18 / 3000 = 333333333333333
    /// @dev Reverts if price is stale or unavailable.
    function getEthWeiPerToken(address token) external view returns (uint256);

    /// @notice Returns true if the price for token is older than maxStaleness.
    function isStale(address token) external view returns (bool);
}
