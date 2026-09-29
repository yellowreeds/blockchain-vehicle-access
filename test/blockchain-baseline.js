const { ethers } = require("hardhat");
const fs = require("fs");

const TRIALS = 5;
const results = [];

function record(scenario, trial, expected, actual, reason) {
    const passed = expected === actual;

    results.push({
        scenario,
        trial,
        expected,
        actual,
        reason,
        passed
    });

    console.log(
        `${scenario} [${trial}/${TRIALS}] -> ${actual} (${reason})`
    );
}

async function issueCredential(contract) {
    // Ordinary application identifiers — no DID
    const data = {
        truckId: "truck001",
        driverId: "driver001",
        plateNumber: "12가3456"
    };

    const nonce = ethers.hexlify(ethers.randomBytes(32));
    const id = ethers.id(nonce);
    const hash = ethers.id(JSON.stringify(data));

    await (
        await contract.issueQR(id, hash, nonce)
    ).wait();

    return {
        id,
        nonce,
        hash,
        data
    };
}

async function main() {
    const QRAccess = await ethers.getContractFactory("QRAccess");
    const contract = await QRAccess.deploy();
    await contract.waitForDeployment();

    console.log("\n=== SMART CONTRACT WITHOUT DID ===");
    console.log("Identity: ordinary truckId/driverId\n");

    // 1. Normal issuance / usage
    console.log("=== NORMAL USE ===");

    for (let i = 1; i <= TRIALS; i++) {
        const credential = await issueCredential(contract);

        await (
            await contract.useQR(credential.id)
        ).wait();

        const state = await contract.getQR(credential.id);

        record(
            "Blockchain-Normal",
            i,
            "USED",
            state[2] ? "USED" : "UNUSED",
            "Blockchain usage state"
        );
    }

    // 2. Replay prevention
    console.log("\n=== REPLAY PREVENTION ===");

    for (let i = 1; i <= TRIALS; i++) {
        const credential = await issueCredential(contract);

        await (
            await contract.useQR(credential.id)
        ).wait();

        try {
            await (
                await contract.useQR(credential.id)
            ).wait();

            record(
                "Blockchain-Replay",
                i,
                "REJECTED",
                "ACCEPTED",
                "Unexpected second use"
            );
        } catch {
            record(
                "Blockchain-Replay",
                i,
                "REJECTED",
                "REJECTED",
                "Already used"
            );
        }
    }

    // 3. Revocation
    console.log("\n=== REVOCATION ===");

    for (let i = 1; i <= TRIALS; i++) {
        const credential = await issueCredential(contract);

        await (
            await contract.revokeQR(credential.id)
        ).wait();

        try {
            await (
                await contract.useQR(credential.id)
            ).wait();

            record(
                "Blockchain-Revocation",
                i,
                "REJECTED",
                "ACCEPTED",
                "Revoked credential used"
            );
        } catch {
            record(
                "Blockchain-Revocation",
                i,
                "REJECTED",
                "REJECTED",
                "Revoked"
            );
        }
    }

    // Export CSV
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
        "results/blockchain-baseline.csv",
        csv
    );

    console.log(
        "\nResults saved to results/blockchain-baseline.csv"
    );
}

main().catch(console.error);