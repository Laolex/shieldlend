// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockZAMA
 * @notice Sepolia testnet mock of the ZAMA token (not official).
 *         18 decimals. Anyone can mint up to 10,000 ZAMA per call for testing.
 */
contract MockZAMA is ERC20 {
    uint256 public constant FAUCET_AMOUNT = 10_000 * 1e18;

    constructor() ERC20("Mock ZAMA Token", "ZAMA") {
        _mint(msg.sender, 1_000_000 * 1e18); // initial supply to deployer
    }

    /// @notice Anyone can mint up to 10,000 ZAMA for testnet use.
    function faucet() external {
        _mint(msg.sender, FAUCET_AMOUNT);
    }

    /// @notice Owner can mint arbitrary amount for testing.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
