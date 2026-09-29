const { ethers } = require("hardhat");
const DID = require("./did");

// Registered vehicle-driver bindings
const vehicleRegistry = new Map();

function registerVehicle(truckDID, driverDID, plateNumber) {
    vehicleRegistry.set(truckDID, {
        driverDID,
        plateNumber
    });
}

// Distance in meters
function distance(lat1, lon1, lat2, lon2) {
    const R = 6371000;
    const rad = x => x * Math.PI / 180;

    const dLat = rad(lat2 - lat1);
    const dLon = rad(lon2 - lon1);

    const a =
        Math.sin(dLat / 2) ** 2 +
        Math.cos(rad(lat1)) *
        Math.cos(rad(lat2)) *
        Math.sin(dLon / 2) ** 2;

    return 2 * R * Math.asin(Math.sqrt(a));
}

// Create temporary signed credential
async function createCredential(
    contract,
    truckDID,
    driverDID,
    plateNumber,
    geofence,
    ttl = 60
) {
    const issuedAt = Date.now();
    const nonce = ethers.hexlify(ethers.randomBytes(32));

    const payload = {
        didTruck: truckDID,
        didDriver: driverDID,
        plateNumber,
        issuedAt,
        expiredAt: issuedAt + ttl * 1000,
        geofence,
        nonce
    };

    const signature = await DID.sign(truckDID, payload);

    const credential = {
        ...payload,
        signature
    };

    // Blockchain identifier derived from nonce
    const id = ethers.id(nonce);

    // Hash exactly what is contained in the signed QR credential
    const credentialHash = ethers.id(
        JSON.stringify(credential)
    );

    await (
        await contract.issueQR(
            id,
            credentialHash,
            nonce
        )
    ).wait();

    return {
        id,
        ...credential
    };
}


// Verify scanned QR credential
async function verifyCredential(contract, credential, location) {

    const {
        id,
        signature,
        ...payload
    } = credential;

    // 1. Verify cryptographic signature
    if (!DID.verify(payload.didTruck, payload, signature))
        return {
            valid: false,
            reason: "Invalid signature"
        };

    // 2. Expiration
    if (Date.now() > payload.expiredAt)
        return {
            valid: false,
            reason: "Expired"
        };

    // 3. Verify registered truck-driver-plate binding
    const registered = vehicleRegistry.get(payload.didTruck);

    if (
        !registered ||
        registered.driverDID !== payload.didDriver ||
        registered.plateNumber !== payload.plateNumber
    )
        return {
            valid: false,
            reason: "Vehicle-driver binding mismatch"
        };

    // 4. Geofence
    const d = distance(
        location.lat,
        location.lon,
        payload.geofence.lat,
        payload.geofence.lon
    );

    if (d > payload.geofence.radius)
        return {
            valid: false,
            reason: "Outside geofence"
        };

    // 5. Read blockchain record
    let state;

    try {
        state = await contract.getQR(id);
    } catch {
        return {
            valid: false,
            reason: "Credential not registered"
        };
    }

    const [
        onChainHash,
        onChainNonce,
        used,
        revoked
    ] = state;

    // 6. Reconstruct hash from scanned credential
    const scannedCredential = {
        ...payload,
        signature
    };

    const scannedHash = ethers.id(
        JSON.stringify(scannedCredential)
    );

    // 7. Credential hash must match blockchain
    if (scannedHash !== onChainHash)
        return {
            valid: false,
            reason: "Credential hash mismatch"
        };

    // 8. Nonce must match blockchain
    if (payload.nonce !== onChainNonce)
        return {
            valid: false,
            reason: "Nonce mismatch"
        };

    // 9. ID must correspond to nonce
    if (ethers.id(payload.nonce) !== id)
        return {
            valid: false,
            reason: "Credential ID mismatch"
        };

    // 10. Blockchain status
    if (revoked)
        return {
            valid: false,
            reason: "Revoked"
        };

    if (used)
        return {
            valid: false,
            reason: "Replay detected"
        };

    // 11. Consume credential
    await (
        await contract.useQR(id)
    ).wait();

    return {
        valid: true,
        reason: "Access granted"
    };
}

module.exports = {
    registerVehicle,
    createCredential,
    verifyCredential
};