const jwt = require("jsonwebtoken");
const fs = require("fs");

// Implemented baseline configuration
const JWT_SECRET = "prototype-secret";
const JWT_ALGORITHM = "HS256";
const TRIALS = 5;

// Centralized in-memory replay blacklist
const blacklist = new Set();
const results = [];

function issueJWT() {
    return jwt.sign(
        {
            truckId: "truck001",
            driverId: "driver001",
            plateNumber: "12가3456"
        },
        JWT_SECRET,
        {
            algorithm: JWT_ALGORITHM,
            expiresIn: "60s",
            jwtid: Math.random().toString(36)
        }
    );
}

function verifyJWT(token) {
    if (blacklist.has(token)) {
        return {
            valid: false,
            reason: "Replay detected"
        };
    }

    try {
        jwt.verify(token, JWT_SECRET, {
            algorithms: [JWT_ALGORITHM]
        });

        blacklist.add(token);

        return {
            valid: true,
            reason: "Access granted"
        };
    } catch {
        return {
            valid: false,
            reason: "Invalid/expired token"
        };
    }
}

function record(scenario, trial, expected, result) {
    const passed = result.valid === expected;

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

function main() {
    console.log("\n=== JWT BASELINE ===");
    console.log("Algorithm:", JWT_ALGORITHM);
    console.log("Blacklist: centralized in-memory Set\n");

    // 1. Normal verification
    console.log("=== NORMAL ACCESS ===");

    for (let i = 1; i <= TRIALS; i++) {
        const token = issueJWT();
        const result = verifyJWT(token);

        record("JWT-Normal", i, true, result);
    }

    // 2. Replay prevention with blacklist available
    console.log("\n=== REPLAY PREVENTION ===");

    for (let i = 1; i <= TRIALS; i++) {
        const token = issueJWT();

        verifyJWT(token);

        const result = verifyJWT(token);

        record("JWT-Replay", i, false, result);
    }

    // 3. Replay after centralized blacklist state is lost
    console.log("\n=== BLACKLIST RESET ===");

    for (let i = 1; i <= TRIALS; i++) {
        const token = issueJWT();

        verifyJWT(token);

        // Simulate loss/reset of centralized replay state
        blacklist.clear();

        const result = verifyJWT(token);

        record("JWT-BlacklistReset", i, true, result);
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
        "results/jwt-baseline.csv",
        csv
    );

    console.log(
        "\nResults saved to results/jwt-baseline.csv"
    );
}

main();