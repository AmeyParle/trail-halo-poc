import {
  generateKeyPair, createOrgDid, createAgentDid,
  createBindingProofCredential, verifyBindingProof, createDidDocument,
} from "@trailprotocol/core";

// ---------------------------------------------------------------------------
// Halo "provable authority" demo
// Shows: a Halo record's principal authority, cryptographically PROVEN,
// not merely asserted. Valid passes; forged fails; revoked fails.
// ---------------------------------------------------------------------------

function statusEntry(did, index) {
  return { id: `${did}#status-${index}`, type: "StatusList2021Entry",
    statusPurpose: "revocation", statusListIndex: String(index),
    statusListCredential: `${did}/status/list` };
}

// --- Setup: org + agent identities, and their DID documents ---
const orgKeys = generateKeyPair();
const orgDid = createOrgDid("acme.com", orgKeys);
const orgDoc = createDidDocument(orgDid, orgKeys);

const agentKeys = generateKeyPair();
const agentDid = createAgentDid("acme.com", agentKeys);
const agentDoc = createDidDocument(agentDid, agentKeys);

// Link the two DID docs so each acknowledges the other (spec Step 1)
orgDoc.alsoKnownAs = [...(orgDoc.alsoKnownAs || []), agentDid];
agentDoc.alsoKnownAs = [...(agentDoc.alsoKnownAs || []), orgDid];

const validFrom = new Date().toISOString();
const validUntil = new Date(Date.now() + 90 * 864e5).toISOString();

// --- The reciprocal binding (org<->agent) ---
const orgLeg = createBindingProofCredential({
  issuerDid: orgDid, subjectDid: agentDid, privateKeyBytes: orgKeys.privateKeyBytes,
  credentialStatus: statusEntry(orgDid, 1), validFrom, validUntil });
const agentLeg = createBindingProofCredential({
  issuerDid: agentDid, subjectDid: orgDid, privateKeyBytes: agentKeys.privateKeyBytes,
  credentialStatus: statusEntry(agentDid, 1), validFrom, validUntil });

// --- A Halo-style record whose principal carries the binding ---
function makeRecord(binding) {
  return {
    tool: "search_customer_db",
    input: { query: "..." },
    principal: { creator_id: agentDid, human_id: orgDid },
    authority_snapshot: { binding }, // <-- the new, provable part
  };
}

// --- verifyAuthority: the bridge from a Halo record to TRAIL verification ---
function verifyAuthority(record, { orgRevoked = false, agentRevoked = false } = {}) {
  const b = record.authority_snapshot?.binding;
  if (!b) return { proven: false, reason: "no binding attached (asserted only)" };
  const res = verifyBindingProof({
    trailCredential: b.agentLeg,        // did:trail side
    foreignCredential: b.orgLeg,        // org side
    trailDidDocument: agentDoc,
    foreignDidDocument: orgDoc,
    trailPublicKeyBytes: agentKeys.publicKeyBytes,
    foreignPublicKeyBytes: orgKeys.publicKeyBytes,
    revocation: { trailCredentialRevoked: agentRevoked, foreignCredentialRevoked: orgRevoked },
  });
  return { proven: res.verified, reason: res.verified ? "authority cryptographically proven" : res.errors.join("; ") };
}

console.log("=================================================================");
console.log("  HALO PROVABLE-AUTHORITY DEMO");
console.log("=================================================================\n");

// CASE 1 — valid binding
const validRecord = makeRecord({ orgLeg, agentLeg });
const r1 = verifyAuthority(validRecord);
console.log("CASE 1  Valid binding");
console.log(`   -> ${r1.proven ? "PASS ✅" : "FAIL ❌"}  (${r1.reason})\n`);

// CASE 2 — forged authority (principal claimed, but NO real binding)
const forgedRecord = makeRecord(null);
forgedRecord.principal.human_id = orgDid; // just *typed in*, unproven
const r2 = verifyAuthority(forgedRecord);
console.log("CASE 2  Forged authority (principal asserted, no binding)");
console.log(`   -> ${r2.proven ? "PASS (unexpected!)" : "FAIL ❌ (correctly rejected)"}  (${r2.reason})\n`);

// CASE 3 — revoked binding
const revokedRecord = makeRecord({ orgLeg, agentLeg });
const r3 = verifyAuthority(revokedRecord, { orgRevoked: true });
console.log("CASE 3  Revoked binding");
console.log(`   -> ${r3.proven ? "PASS (unexpected!)" : "FAIL ❌ (correctly rejected)"}  (${r3.reason})\n`);

console.log("=================================================================");
console.log("  Valid authority verifies. Forged and revoked are caught.");
console.log("  Asserted -> Proven.");
console.log("=================================================================");
