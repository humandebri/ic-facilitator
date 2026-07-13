// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract TestDepositToken {
    string public constant name = "x402 Amoy Test Token";
    string public constant symbol = "X402T";
    uint8 public constant decimals = 18;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}

contract FixedAmountDepositCollector {
    TestDepositToken public immutable token;
    uint256 public immutable amount;

    constructor(TestDepositToken token_, uint256 amount_) {
        token = token_;
        amount = amount_;
    }

    fallback() external {
        require(token.transfer(msg.sender, amount), "transfer failed");
        assembly {
            mstore(0, 1)
            return(0, 32)
        }
    }
}

