// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Address.sol";

contract Wallet {
    address public _beneficiary;
    error notReceiveData();
    error WithdrawFailed();

    constructor() payable {
        _beneficiary = msg.sender;
    }

    function _mySubfuc() private {
        if (msg.data.length != 0) {
            revert notReceiveData();
        }
        Address.sendValue(payable(_beneficiary), msg.value);
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

    receive() external payable {
        _mySubfuc();
    }
}

