const { Wallet, verifyMessage } = require("ethers");

// Simple in-memory DID registry
const registry = new Map();

function createDID(name) {
    const wallet = Wallet.createRandom();
    const did = `did:vehicle:${name}`;

    registry.set(did, wallet);
    return did;
}

function sign(did, data) {
    const wallet = registry.get(did);
    if (!wallet) throw new Error("DID not found");

    return wallet.signMessage(JSON.stringify(data));
}

function verify(did, data, signature) {
    const wallet = registry.get(did);
    if (!wallet) return false;

    const signer = verifyMessage(JSON.stringify(data), signature);
    return signer === wallet.address;
}

// Replace cryptographic key while keeping the same DID
function rotateKey(did) {
    if (!registry.has(did))
        throw new Error("DID not found");

    registry.set(did, Wallet.createRandom());
}

module.exports = {
    createDID,
    sign,
    verify,
    rotateKey
};