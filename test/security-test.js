const { ethers } = require("hardhat");
const DID = require("../did");
const Backend = require("../backend");

const jwt = require("jsonwebtoken");

const JWT_SECRET = "prototype-secret";
const jwtBlacklist = new Set();

const QRCode = require("qrcode");
const fs = require("fs");

if (!fs.existsSync("output")) {
    fs.mkdirSync("output");
}

function issueJWT(data) {
    return jwt.sign(data, JWT_SECRET, {
        expiresIn: "60s",
        jwtid: Math.random().toString(36)
    });
}

function verifyJWT(token) {
    if (jwtBlacklist.has(token))
        return { valid: false, reason: "Replay detected" };

    try {
        jwt.verify(token, JWT_SECRET);
        jwtBlacklist.add(token);
        return { valid: true, reason: "Access granted" };
    } catch {
        return { valid: false, reason: "Invalid/expired token" };
    }
}

async function main() {
    // Deploy contract
    const QRAccess = await ethers.getContractFactory("QRAccess");
    const contract = await QRAccess.deploy();
    await contract.waitForDeployment();

    // Create identities
    const truckDID = DID.createDID("truck001");
    const driverDID = DID.createDID("driver001");

    // Register authorized truck-driver-plate binding
    Backend.registerVehicle(
        truckDID,
        driverDID,
        "12가3456"
    );

    const gate = {
        lat: 37.5665,
        lon: 126.9780,
        radius: 100
    };

    console.log("\n=== SECURITY TEST ===");

    // 1. Normal access
    let qr = await Backend.createCredential(
        contract, truckDID, driverDID, "12가3456", gate
    );

    // Generate actual QR image
    await QRCode.toFile(
        "output/temporary-credential.png",
        JSON.stringify(qr),
        {
            width: 500,
            margin: 2
        }
    );

    console.log("QR image: output/temporary-credential.png");
    console.log("Normal:",
        await Backend.verifyCredential(contract, qr, gate)
    );

    console.log("Replay:",
        await Backend.verifyCredential(contract, qr, gate)
    );

    // Blockchain credential mismatch
    const mismatchQR = await Backend.createCredential(
        contract, truckDID, driverDID, "12가3456", gate
    );

    const otherQR = await Backend.createCredential(
        contract, truckDID, driverDID, "12가3456", gate
    );

    mismatchQR.id = otherQR.id;

    console.log("Blockchain mismatch:",
        await Backend.verifyCredential(contract, mismatchQR, gate)
    );

    // Revocation
    qr = await Backend.createCredential(
        contract, truckDID, driverDID, "12가3456", gate
    );
    await (await contract.revokeQR(qr.id)).wait();

    console.log("Revoked:",
        await Backend.verifyCredential(contract, qr, gate)
    );

    // 4. Expiration
    qr = await Backend.createCredential(
        contract, truckDID, driverDID, "12가3456", gate, 1
    );

    await new Promise(r => setTimeout(r, 1100));

    console.log("Expired:",
        await Backend.verifyCredential(contract, qr, gate)
    );

    // 5. Outside geofence
    qr = await Backend.createCredential(
        contract, truckDID, driverDID, "12가3456", gate
    );

    console.log("Geofence:",
        await Backend.verifyCredential(contract, qr, {
            lat: 37.5765,
            lon: 126.9780
        })
    );

    // 6. Payload tampering
    qr = await Backend.createCredential(
        contract, truckDID, driverDID, "12가3456", gate
    );

    qr.plateNumber = "99가9999";

    console.log("Tampering:",
        await Backend.verifyCredential(contract, qr, gate)
    );

    // 7. DID key rotation
    qr = await Backend.createCredential(
        contract, truckDID, driverDID, "12가3456", gate
    );

    DID.rotateKey(truckDID);

    console.log("Old key after rotation:",
        await Backend.verifyCredential(contract, qr, gate)
    );

    const newQR = await Backend.createCredential(
        contract, truckDID, driverDID, "12가3456", gate
    );

    console.log("New key after rotation:",
        await Backend.verifyCredential(contract, newQR, gate)
    );

    // 8. JWT baseline
    console.log("\n=== JWT BASELINE ===");

    const token = issueJWT({
        truckId: "truck001",
        driverId: "driver001",
        plateNumber: "12가3456"
    });

    console.log("Normal:",
        verifyJWT(token)
    );

    console.log("Replay:",
        verifyJWT(token)
    );

    // Simulate loss/reset of centralized blacklist
    jwtBlacklist.clear();

    console.log("Replay after blacklist reset:",
        verifyJWT(token)
    );


    // 9. Smart contract without DID
    console.log("\n=== SMART CONTRACT WITHOUT DID ===");

    const normalTruckId = "truck001";
    const normalDriverId = "driver001";

    const nonce = ethers.hexlify(ethers.randomBytes(32));
    const id = ethers.id(nonce);

    const data = {
        truckId: normalTruckId,
        driverId: normalDriverId,
        plateNumber: "12가3456"
    };

    const hash = ethers.id(JSON.stringify(data));

    await (await contract.issueQR(id, hash, nonce)).wait();

    console.log("Identity:", data);

    let state = await contract.getQR(id);

    console.log("Initial blockchain state:", {
        used: state[2],
        revoked: state[3]
    });

    await (await contract.useQR(id)).wait();

    state = await contract.getQR(id);

    console.log("After use:", {
        used: state[2],
        revoked: state[3]
    });

}

main().catch(console.error);