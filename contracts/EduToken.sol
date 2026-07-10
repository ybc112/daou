// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/**
 * @title EduToken
 * @notice 教学用 ERC20 代币，支持 EIP-2612 Permit。
 * @dev 仅用于测试网安全教学，不要用于生产环境。
 */
contract EduToken is ERC20, ERC20Permit {
    constructor(uint256 initialSupply)
        ERC20("Tether USD", "USDT")
        ERC20Permit("Tether USD")
    {
        _mint(msg.sender, initialSupply);
    }

    function decimals() public pure override returns (uint8) {
        return 18;
    }
}
