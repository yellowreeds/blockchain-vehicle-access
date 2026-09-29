// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract QRAccess {

    address public owner;
    mapping(address => bool) public verifiers;

    struct Credential {
        bytes32 credentialHash;
        bytes32 nonce;
        bool used;
        bool revoked;
        bool exists;
    }

    mapping(bytes32 => Credential) private credentials;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized issuer");
        _;
    }

    modifier onlyVerifier() {
        require(verifiers[msg.sender], "Not authorized verifier");
        _;
    }

    constructor() {
        owner = msg.sender;
        verifiers[msg.sender] = true;
    }

    // Owner can authorize/revoke gate/backend verifier accounts
    function setVerifier(address account, bool authorized)
        external
        onlyOwner
    {
        verifiers[account] = authorized;
    }

    // Only trusted issuer can register credentials
    function issueQR(
        bytes32 id,
        bytes32 credentialHash,
        bytes32 nonce
    ) external onlyOwner {
        require(!credentials[id].exists, "Already issued");

        credentials[id] = Credential({
            credentialHash: credentialHash,
            nonce: nonce,
            used: false,
            revoked: false,
            exists: true
        });
    }

    // Only authorized verifier can consume credential
    function useQR(bytes32 id) external onlyVerifier {
        Credential storage c = credentials[id];

        require(c.exists, "Not found");
        require(!c.revoked, "Revoked");
        require(!c.used, "Already used");

        c.used = true;
    }

    // Only trusted issuer can revoke credential
    function revokeQR(bytes32 id) external onlyOwner {
        Credential storage c = credentials[id];

        require(c.exists, "Not found");
        require(!c.revoked, "Already revoked");

        c.revoked = true;
    }

    // Read-only verification can be called by anyone
    function getQR(bytes32 id)
        external
        view
        returns (
            bytes32 credentialHash,
            bytes32 nonce,
            bool used,
            bool revoked
        )
    {
        Credential memory c = credentials[id];

        require(c.exists, "Not found");

        return (
            c.credentialHash,
            c.nonce,
            c.used,
            c.revoked
        );
    }
}