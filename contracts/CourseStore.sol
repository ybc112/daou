// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title CourseStore
 * @notice A simple BNB Chain course/product checkout contract.
 * @dev Supports native BNB payments and exact BEP20 token payments.
 */
contract CourseStore is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    struct Product {
        string title;
        uint256 bnbPrice;
        uint256 tokenPrice;
        bool active;
    }

    address payable public treasury;
    IERC20 public paymentToken;

    mapping(uint256 => Product) public products;

    event ProductUpdated(uint256 indexed productId, string title, uint256 bnbPrice, uint256 tokenPrice, bool active);
    event TreasuryUpdated(address indexed treasury);
    event PaymentTokenUpdated(address indexed token);
    event Purchased(
        address indexed buyer,
        uint256 indexed productId,
        string title,
        address indexed paymentAsset,
        uint256 amount
    );

    constructor(address initialOwner, address payable initialTreasury, address initialPaymentToken) Ownable(initialOwner) {
        require(initialTreasury != address(0), "Invalid treasury");
        treasury = initialTreasury;
        paymentToken = IERC20(initialPaymentToken);
    }

    function setTreasury(address payable newTreasury) external onlyOwner {
        require(newTreasury != address(0), "Invalid treasury");
        treasury = newTreasury;
        emit TreasuryUpdated(newTreasury);
    }

    function setPaymentToken(address newPaymentToken) external onlyOwner {
        paymentToken = IERC20(newPaymentToken);
        emit PaymentTokenUpdated(newPaymentToken);
    }

    function setProduct(
        uint256 productId,
        string calldata title,
        uint256 bnbPrice,
        uint256 tokenPrice,
        bool active
    ) external onlyOwner {
        require(bytes(title).length > 0, "Empty title");
        require(bnbPrice > 0 || tokenPrice > 0, "Empty price");
        products[productId] = Product({
            title: title,
            bnbPrice: bnbPrice,
            tokenPrice: tokenPrice,
            active: active
        });
        emit ProductUpdated(productId, title, bnbPrice, tokenPrice, active);
    }

    function purchaseWithBNB(uint256 productId) external payable nonReentrant {
        Product memory product = products[productId];
        require(product.active, "Product inactive");
        require(product.bnbPrice > 0, "BNB disabled");
        require(msg.value == product.bnbPrice, "Incorrect BNB amount");

        (bool sent, ) = treasury.call{value: msg.value}("");
        require(sent, "Transfer failed");

        emit Purchased(msg.sender, productId, product.title, address(0), msg.value);
    }

    function purchaseWithToken(uint256 productId) external nonReentrant {
        Product memory product = products[productId];
        require(product.active, "Product inactive");
        require(address(paymentToken) != address(0), "Token not configured");
        require(product.tokenPrice > 0, "Token disabled");

        paymentToken.safeTransferFrom(msg.sender, treasury, product.tokenPrice);

        emit Purchased(msg.sender, productId, product.title, address(paymentToken), product.tokenPrice);
    }
}
