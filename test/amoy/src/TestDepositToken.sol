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

contract TestEip3009Token is TestDepositToken {
    string public constant version = "1";
    bytes32 public immutable DOMAIN_SEPARATOR;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(this)
            )
        );
    }

    function supportsReceiveAuthorization() external pure returns (bool) {
        return true;
    }

    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp > validAfter, "authorization not yet valid");
        require(block.timestamp <= validBefore, "authorization expired");
        require(!authorizationState[from][nonce], "authorization already used");

        bytes32 structHash = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );
        address signer = ecrecover(keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)), v, r, s);
        require(signer == from, "invalid authorization signature");

        authorizationState[from][nonce] = true;
        require(balanceOf[from] >= value, "insufficient balance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external {
        require(to == msg.sender, "receive authorization must target caller");
        require(block.timestamp > validAfter, "authorization not yet valid");
        require(block.timestamp <= validBefore, "authorization expired");
        require(!authorizationState[from][nonce], "authorization already used");

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
                ),
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );
        address signer = _recover(
            keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)), signature
        );
        require(signer == from, "invalid authorization signature");

        authorizationState[from][nonce] = true;
        require(balanceOf[from] >= value, "insufficient balance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address signer) {
        require(signature.length == 65, "invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        return ecrecover(digest, v, r, s);
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

interface IERC3009TestToken {
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external;
}

interface IERC20TestToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract TestErc3009DepositCollector {
    address public immutable x402BatchSettlement;

    constructor(address batchSettlement) {
        require(batchSettlement != address(0), "zero batch settlement");
        x402BatchSettlement = batchSettlement;
    }

    function collect(
        address payer,
        address token,
        uint256 amount,
        bytes32 channelId,
        bytes calldata collectorData
    ) external {
        require(msg.sender == x402BatchSettlement, "only batch settlement");
        (uint256 validAfter, uint256 validBefore, uint256 salt, bytes memory signature) =
            abi.decode(collectorData, (uint256, uint256, uint256, bytes));
        bytes32 nonce = keccak256(abi.encode(channelId, salt));
        IERC3009TestToken(token).receiveWithAuthorization(
            payer, address(this), amount, validAfter, validBefore, nonce, signature
        );
        require(IERC20TestToken(token).transfer(x402BatchSettlement, amount), "forward failed");
    }
}
