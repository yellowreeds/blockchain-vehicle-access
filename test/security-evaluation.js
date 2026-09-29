const { ethers } = require("hardhat");
const DID = require("../did");
const Backend = require("../backend");
const fs = require("fs");

const TRIALS = 5;
const results = [];

function record(scenario, trial, expected, result) {
    const passed =
        result.valid === expected;

    results.push({
        scenario,
        trial,
        expected: expected ? "ACCEPTED" : "REJECTED",
        actual: result.valid ? "ACCEPTED" : "REJECTED",
        reason: result.reason,
        passed
    });

    console.log(
        `${scenario} [${trial}/${TRIALS}] ->`,
        result.valid ? "ACCEPTED" : "REJECTED",
        `(${result.reason})`
    );
}

async function main() {
    const QRAccess = await ethers.getContractFactory("QRAccess");
    const contract = await QRAccess.deploy();
    await contract.waitForDeployment();

    const truckDID = DID.createDID("truck001");
    const driverDID = DID.createDID("driver001");

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

    console.log("\n=== SECURITY EVALUATION ===\n");

    // 1. Expiry enforcement
    console.log("=== EXPIRY ENFORCEMENT ===");

    for (let i = 1; i <= TRIALS; i++) {
        const qr = await Backend.createCredential(
            contract,
            truckDID,
            driverDID,
            "12가3456",
            gate,
            1
        );

        await new Promise(r => setTimeout(r, 1100));

        const result = await Backend.verifyCredential(
            contract,
            qr,
            gate
        );

        record("Expiry", i, false, result);
    }

    // 2. Replay prevention
    console.log("\n=== REPLAY PREVENTION ===");

    for (let i = 1; i <= TRIALS; i++) {
        const qr = await Backend.createCredential(
            contract,
            truckDID,
            driverDID,
            "12가3456",
            gate
        );

        // First use must succeed
        await Backend.verifyCredential(contract, qr, gate);

        // Second use must be rejected
        const result = await Backend.verifyCredential(
            contract,
            qr,
            gate
        );

        record("Replay", i, false, result);
    }

    // 3. Out-of-geofence detection
    console.log("\n=== GEOFENCE DETECTION ===");

    for (let i = 1; i <= TRIALS; i++) {
        const qr = await Backend.createCredential(
            contract,
            truckDID,
            driverDID,
            "12가3456",
            gate
        );

        const outsideLocation = {
            lat: 37.5765,
            lon: 126.9780
        };

        const result = await Backend.verifyCredential(
            contract,
            qr,
            outsideLocation
        );

        record("Geofence", i, false, result);
    }

    // 4. Revocation
    console.log("\n=== REVOCATION ===");

    for (let i = 1; i <= TRIALS; i++) {
        const qr = await Backend.createCredential(
            contract,
            truckDID,
            driverDID,
            "12가3456",
            gate
        );

        await (await contract.revokeQR(qr.id)).wait();

        const result = await Backend.verifyCredential(
            contract,
            qr,
            gate
        );

        record("Revocation", i, false, result);
    }

    // 5. Payload/signature tampering
    console.log("\n=== PAYLOAD TAMPERING ===");

    const tamperFields = [
        "expiredAt",
        "didTruck",
        "didDriver",
        "plateNumber",
        "nonce"
    ];

    for (const field of tamperFields) {
        for (let i = 1; i <= TRIALS; i++) {

            const qr = await Backend.createCredential(
                contract,
                truckDID,
                driverDID,
                "12가3456",
                gate
            );

            // Modify payload but keep original signature
            if (field === "expiredAt")
                qr.expiredAt += 60000;

            if (field === "didTruck")
                qr.didTruck = "did:vehicle:fakeTruck";

            if (field === "didDriver")
                qr.didDriver = "did:vehicle:fakeDriver";

            if (field === "plateNumber")
                qr.plateNumber = "99가9999";

            if (field === "nonce")
                qr.nonce = ethers.hexlify(ethers.randomBytes(32));

            const result = await Backend.verifyCredential(
                contract,
                qr,
                gate
            );

            record(`Tamper-${field}`, i, false, result);
        }
    }
    // 6. DID key rotation
    console.log("\n=== DID KEY ROTATION ===");

    for (let i = 1; i <= TRIALS; i++) {

        // Credential signed using current key
        const oldQR = await Backend.createCredential(
            contract,
            truckDID,
            driverDID,
            "12가3456",
            gate
        );

        // Rotate key while keeping the same DID
        DID.rotateKey(truckDID);

        const oldResult = await Backend.verifyCredential(
            contract,
            oldQR,
            gate
        );

        record("KeyRotation-OldKey", i, false, oldResult);

        // Credential signed using new key
        const newQR = await Backend.createCredential(
            contract,
            truckDID,
            driverDID,
            "12가3456",
            gate
        );

        const newResult = await Backend.verifyCredential(
            contract,
            newQR,
            gate
        );

        record("KeyRotation-NewKey", i, true, newResult);
    }
    // Export results to CSV
    if (!fs.existsSync("results")) {
        fs.mkdirSync("results");
    }

    const header = [
        "scenario",
        "trial",
        "expected",
        "actual",
        "reason",
        "passed"
    ];

    const rows = results.map(r => [
        r.scenario,
        r.trial,
        r.expected,
        r.actual,
        r.reason,
        r.passed
    ]);

    const csv = [
        header.join(","),
        ...rows.map(row => row.join(","))
    ].join("\n");

    fs.writeFileSync(
        "results/security-evaluation.csv",
        csv
    );

    console.log(
        "\nResults saved to results/security-evaluation.csv"
    );
}

main().catch(console.error);