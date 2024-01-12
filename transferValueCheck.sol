// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.20;

import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract Wallet {
    address public _cosigner;
    address public _beneficiary;
    uint256 public constant one_minute = 1 minutes;
    uint256 expireTime;
    mapping(string => bool) sigvalue;
    address public _owner;
    error notSatifiedSig();
    error WithdrawFailed();

    constructor(
        address cosigner,
        address beneficiary,
        uint32 expire
    ) payable {
        _cosigner = cosigner;
        _beneficiary = beneficiary;
        _owner = msg.sender;
        expireTime = expire * one_minute;
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "Only operator can mint new souls");
        _;
    }

    function updateOwner(address newowner) external onlyOwner {
        require(newowner != address(0), "Invalid Owner");
        _owner = newowner;
    }

    function updateSigner(address newsigner) external onlyOwner {
        require(newsigner != address(0), "Invalid Signer");
        _cosigner = newsigner;
    }

    function updateBeneficiary(address newbene) external onlyOwner {
        require(newbene != address(0), "Invalid Signer");
        _beneficiary = newbene;
    }

    function updateExpire(uint32 expire) external onlyOwner {
        expireTime = expire * one_minute;
    }

    function getRidState(string memory rid) external view returns (bool) {
        return sigvalue[rid];
    }

    /**
     * @dev Validates the the given signature.
     */
    function assertValidCosign(uint256 value, bytes memory data) internal {
        (
            uint32 qty,
            string memory requestId,
            uint64 timestamp,
            bytes memory sig
        ) = decode(data);
        require((expireTime + timestamp >= block.timestamp), "HAS_Expired");
        require((!sigvalue[requestId]), "HAS_USED");
        sigvalue[requestId] = true;

        if (
            !SignatureChecker.isValidSignatureNow(
                _cosigner,
                getCosignDigest(
                    msg.sender,
                    qty,
                    _chainID(),
                    requestId,
                    timestamp
                ),
                sig
            )
        ) {
            revert notSatifiedSig();
        }
        uint256 msgvalue = value;
        uint256 qtyvalue = qty;
        require((msgvalue == qtyvalue * (10**14)), "INVALID_VALUE");
    }

        /**
     * @dev Validates the the given signature.
     */
    function _assertValidCosign(uint256 value, bytes memory data) public view{
        (
            uint32 qty,
            string memory requestId,
            uint64 timestamp,
            bytes memory sig
        ) = decode(data);
        require((expireTime + timestamp >= block.timestamp), "HAS_Expired");
        require((!sigvalue[requestId]), "HAS_USED");
      
        if (
            !SignatureChecker.isValidSignatureNow(
                _cosigner,
                getCosignDigest(
                    msg.sender,
                    qty,
                    _chainID(),
                    requestId,
                    timestamp
                ),
                sig
            )
        ) {
            revert notSatifiedSig();
        }
        uint256 msgvalue = value;
        uint256 qtyvalue = qty;
        require((msgvalue == qtyvalue * (10**14)), "INVALID_VALUE");
    }

    /**
     * @dev Returns data hash for the given sender, qty and timestamp.
     */
    function getCosignDigest(
        address sender,
        uint32 qty,
        uint32 chainId,
        string memory requestId,
        uint64 timestamp
    ) internal view returns (bytes32) {
        bytes32 _msgHash = keccak256(
            abi.encodePacked(
                address(this),
                sender,
                _cosigner,
                qty,
                chainId,
                requestId,
                timestamp
            )
        );
        return toEthSignedMessageHash(_msgHash);
    }

    /**
     * @dev Returns chain id.
     */
    function _chainID() public view returns (uint32) {
        uint32 chainID;
        assembly {
            chainID := chainid()
        }
        return chainID;
    }

    function abiEnCode(
        uint32 qty,
        string memory requestId,
        uint64 timestamp,
        bytes memory sig
    ) external view returns (bytes memory data) {
        data = abi.encode(
            address(this),
            msg.sender,
            _cosigner,
            qty,
            _chainID(),
            requestId,
            timestamp,
            sig
        );
    }

    function decode(bytes memory data)
        public
        pure
        returns (
            uint32 qty,
            string memory requestId,
            uint64 timestamp,
            bytes memory sig
        )
    {
        (, , , qty, , requestId, timestamp, sig) = abi.decode(
            data,
            (address, address, address, uint32, uint32, string, uint64, bytes)
        );
    }

    function gettimestamp() public view returns (uint256) {
        return block.timestamp;
    }

    function toEthSignedMessageHash(bytes32 hash)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
            );
    }

    function _mySubfuc() private pure {
        if (msg.data.length == 0) {
            revert notSatifiedSig();
        }
    }

    /**
     * @dev Withdraws funds by owner.
     */
    function withdraw() external {
        require(msg.sender == _beneficiary);
        uint256 value = address(this).balance;
        (bool success, ) = msg.sender.call{value: value}("");
        if (!success) revert WithdrawFailed();
    }

    fallback() external payable {
        assertValidCosign(msg.value, msg.data);
        Address.sendValue(payable(_beneficiary), msg.value);
    }

    receive() external payable {
        _mySubfuc();
    }
}
