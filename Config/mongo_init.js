// ================================================================
//  Cyber Threat Intelligence Hub — MongoDB Initialization Script
//  Run once on first setup to create database + collections
// ================================================================
//
//  How to run:
//    mongosh < config/mongo_init.js
//  Or inside Docker:
//    docker exec -i mongodb mongosh < config/mongo_init.js
// ================================================================

// Switch to threatdb database
db = db.getSiblingDB("threatdb");

print("================================================================");
print("  TIP — MongoDB Initialization");
print("================================================================");

// ── Create Collections ──────────────────────────────────────────

// 1. indicators — stores all normalized threat indicators
db.createCollection("indicators", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["value", "type", "source", "risk_score"],
            properties: {
                value:      { bsonType: "string",  description: "IP, domain, or URL" },
                type:       { bsonType: "string",  enum: ["ip", "domain", "url", "hash", "unknown"] },
                source:     { bsonType: "string",  description: "Feed source name" },
                risk_score: { bsonType: "int",     minimum: 0, maximum: 100 },
                severity:   { bsonType: "string",  enum: ["HIGH", "MEDIUM", "LOW"] },
                blocked:    { bsonType: "bool" },
            }
        }
    }
});
print("  ✅ Created collection: indicators");

// 2. blocked_ips — tracks currently blocked IP addresses
db.createCollection("blocked_ips");
print("  ✅ Created collection: blocked_ips");

// 3. enforcement_audit — immutable audit log of all actions
db.createCollection("enforcement_audit");
print("  ✅ Created collection: enforcement_audit");

// 4. feeds_log — tracks when each feed was last pulled
db.createCollection("feeds_log");
print("  ✅ Created collection: feeds_log");


// ── Create Indexes ──────────────────────────────────────────────

// indicators indexes
db.indicators.createIndex({ value: 1 },        { unique: true, name: "idx_value" });
db.indicators.createIndex({ type: 1 },          { name: "idx_type" });
db.indicators.createIndex({ risk_score: -1 },   { name: "idx_risk_score" });
db.indicators.createIndex({ severity: 1 },      { name: "idx_severity" });
db.indicators.createIndex({ source: 1 },        { name: "idx_source" });
db.indicators.createIndex({ blocked: 1 },       { name: "idx_blocked" });
db.indicators.createIndex({ last_seen: -1 },    { name: "idx_last_seen" });
print("  ✅ Indexes created for: indicators");

// blocked_ips indexes
db.blocked_ips.createIndex({ ip: 1 },           { unique: true, name: "idx_ip" });
db.blocked_ips.createIndex({ blocked_at: -1 },  { name: "idx_blocked_at" });
print("  ✅ Indexes created for: blocked_ips");

// enforcement_audit indexes
db.enforcement_audit.createIndex({ timestamp: -1 }, { name: "idx_timestamp" });
db.enforcement_audit.createIndex({ action: 1 },     { name: "idx_action" });
db.enforcement_audit.createIndex({ ip: 1 },         { name: "idx_audit_ip" });
print("  ✅ Indexes created for: enforcement_audit");


// ── Insert Sample Data ──────────────────────────────────────────

var now = new Date().toISOString();

// Sample indicator
db.indicators.insertOne({
    id:          "sample_001",
    value:       "192.0.2.1",
    type:        "ip",
    source:      "Feodo_Tracker",
    risk_score:  90,
    severity:    "HIGH",
    tags:        ["botnet", "c2", "sample"],
    description: "Sample entry — replace with real data",
    country:     "XX",
    first_seen:  now,
    last_seen:   now,
    blocked:     false,
});
print("  ✅ Sample indicator inserted");

// Sample feed log
db.feeds_log.insertOne({
    feed:        "Feodo_Tracker",
    last_pulled: now,
    count:       0,
    status:      "initialized",
});
print("  ✅ Sample feed log inserted");


// ── Create Admin User (optional, for production) ────────────────
// Uncomment below for production setup:
//
// db.createUser({
//     user: "tip_user",
//     pwd:  "changeme_strong_password",
//     roles: [{ role: "readWrite", db: "threatdb" }]
// });
// print("  ✅ MongoDB user created");


print("================================================================");
print("  MongoDB initialization complete!");
print("  Database: threatdb");
print("  Collections: indicators, blocked_ips, enforcement_audit, feeds_log");
print("================================================================");
