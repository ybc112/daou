// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./EduSwap.sol";

contract EduSwapFactory {
    event Deployed(address indexed addr, bytes32 salt);

    function predictAddress(bytes32 salt) public view returns (address) {
        bytes memory bytecode = abi.encodePacked(
            type(EduSwap).creationCode,
            abi.encode("EduSwap")
        );
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecode)
            )
        );
        return address(uint160(uint256(hash)));
    }

    function deploy(bytes32 salt, address token) external returns (address) {
        address predicted = predictAddress(salt);
        require(!_isContract(predicted), "Already deployed");

        EduSwap router = new EduSwap{salt: salt}("EduSwap");
        router.addSupportedToken(token);
        emit Deployed(address(router), salt);
        return address(router);
    }

    function _isContract(address addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}
