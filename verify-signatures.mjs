// ---------------------------------------------------------------------------
// Adversarial suite — every claim, actually executed.
//
//   node verify-signatures.mjs        (no API key needed)
//
// Confirms untouched records verify, then that each tampering attempt fails.
// ---------------------------------------------------------------------------

import {
  generateKeyPair, createOrgDid, createAgentDid, createDidDocument,
  createBindingProofCredential, verifyBindingProof, createProof, verifyProof,
} from "@trailprotocol/core";
import { Recorder, build, verifyLog } from "halo-record";
import { existsSync, unlinkSync, readFileSync } from "fs";

const LOG = "./verify.jsonl";
if (existsSync(LOG)) unlinkSync(LOG);

// ── identities ─────────────────────────────────────────────────────────────
const orgKeys   = generateKeyPair();
const orgDid    = createOrgDid("acme.com", orgKeys.publicKeyMultibase);
const orgDoc    = createDidDocument(orgDid, orgKeys);
const agentKeys = generateKeyPair();
const agentDid  = createAgentDid("supportbot.acme.com", agentKeys.publicKeyMultibase);
const agentDoc  = createDidDocument(agentDid, agentKeys);
orgDoc.alsoKnownAs = [agentDid]; agentDoc.alsoKnownAs = [orgDid];

const REGISTRY = { [orgDid]: orgDoc, [agentDid]: agentDoc };
function resolveKey(did, vmId) {
  const doc = REGISTRY[did];
  if (!doc) throw new Error(`cannot resolve ${did}`);
  const vm = (doc.verificationMethod || []).find(v => v.id === vmId);
  if (!vm) throw new Error(`no verification method ${vmId}`);
  if (!(doc.assertionMethod || []).includes(vmId))
    throw new Error(`${vmId} not authorized for assertion`);
  return new Uint8Array(Buffer.from(vm.publicKeyJwk.x, "base64url"));
}

const validFrom = new Date().toISOString();
const validUntil = new Date(Date.now() + 90 * 864e5).toISOString();
const st = (d, i) => ({ id:`${d}#status-${i}`, type:"StatusList2021Entry",
  statusPurpose:"revocation", statusListIndex:String(i), statusListCredential:`${d}/status/list` });

const binding = {
  orgLeg: createBindingProofCredential({ issuerDid:orgDid, subjectDid:agentDid,
    privateKeyBytes:orgKeys.privateKeyBytes, credentialStatus:st(orgDid,1), validFrom, validUntil }),
  agentLeg: createBindingProofCredential({ issuerDid:agentDid, subjectDid:orgDid,
    privateKeyBytes:agentKeys.privateKeyBytes, credentialStatus:st(agentDid,1), validFrom, validUntil }),
};

function issueScopeGrant(tools, signWith = orgKeys.privateKeyBytes) {
  const doc = {
    "@context":["https://www.w3.org/ns/credentials/v2","https://trailprotocol.org/ns/credentials/v1"],
    type:["VerifiableCredential","ScopeGrantCredential"],
    issuer: orgDid, validFrom, validUntil,
    credentialSubject:{ id: agentDid, authorizedTools: tools },
  };
  return { ...doc, proof: createProof(doc, signWith, `${orgDid}#key-1`, "assertionMethod") };
}
const scopeGrant = issueScopeGrant(["search_docs","get_weather"]);

function verifyAuthority(tool, grant) {
  const res = verifyBindingProof({
    trailCredential:binding.agentLeg, foreignCredential:binding.orgLeg,
    trailDidDocument:agentDoc, foreignDidDocument:orgDoc,
    trailPublicKeyBytes:  resolveKey(agentDid, `${agentDid}#key-1`),
    foreignPublicKeyBytes: resolveKey(orgDid,   `${orgDid}#key-1`),
    revocation:{ trailCredentialRevoked:false, foreignCredentialRevoked:false },
  });
  if (!res.verified) return { proven:false, reason:"binding invalid" };
  const { proof, ...grantDoc } = grant;
  if (grantDoc.issuer !== orgDid)
    return { proven:false, reason:"scope grant not issued by the bound org" };
  if (!verifyProof(grantDoc, proof, resolveKey(grantDoc.issuer, proof.verificationMethod)))
    return { proven:false, reason:"scope grant signature invalid" };
  if (grantDoc.credentialSubject.id !== agentDid)
    return { proven:false, reason:"grant issued to a different agent" };
  if (!grantDoc.credentialSubject.authorizedTools.includes(tool))
    return { proven:false, reason:`"${tool}" not in the org-signed grant` };
  return { proven:true, reason:"binding + org-signed scope verified" };
}

// ── write a chain ──────────────────────────────────────────────────────────
const recorder = new Recorder(LOG);
function record(tool, args) {
  const c = verifyAuthority(tool, scopeGrant);
  const rec = build("tool_call","security",{
    tool, toolInput:args, agent:{ id:agentDid, name:"SupportBot" }, sessionId:"verify",
    decision: c.proven ? "allowed" : "denied",
    principal:{ creator_id:agentDid, human_id:orgDid },
    verification:{ status: c.proven ? "allowed" : "blocked" },
    data:{ authority_binding:binding, scope_grant:scopeGrant, authority_reason:c.reason },
  });
  const { integrity, ...signable } = rec;
  rec.data.agent_proof = createProof(signable, agentKeys.privateKeyBytes,
    `${agentDid}#key-1`, "assertionMethod");
  recorder.append(rec);
  return c;
}

function checkSig(rec) {
  const { integrity, ...rest } = rec;
  const proof = rest.data?.agent_proof;
  if (!proof) return false;
  const signable = { ...rest, data:{ ...rest.data } };
  delete signable.data.agent_proof;
  try { return verifyProof(signable, proof, resolveKey(rest.agent.id, proof.verificationMethod)); }
  catch { return false; }   // unresolvable DID = cannot verify
}

const line = (l, v, want) =>
  console.log(`  ${l.padEnd(46)} ${String(v).padEnd(6)} ${v === want ? "✓" : "✗ UNEXPECTED"}`);

console.log("\nIDENTITIES");
console.log("  org  :", orgDid);
console.log("  agent:", agentDid);
line("DID suffixes are distinct", orgDid.split("-").pop() !== agentDid.split("-").pop(), true);

record("search_docs",     { query:"onboarding" });
record("get_weather",     { city:"Chicago" });
record("delete_database", { confirm:"free up space" });

const recs = readFileSync(LOG,"utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
const clone = i => JSON.parse(JSON.stringify(recs[i]));

console.log("\nBASELINE");
const v = verifyLog(LOG);
line("halo verifyLog ok", v.ok, true);
line("chain prev_hash links match", recs.every((r,i) =>
  i === 0 ? r.integrity.prev_hash === "0".repeat(64)
          : r.integrity.prev_hash === recs[i-1].integrity.hash), true);
line("every record signature valid", recs.every(checkSig), true);
line("out-of-scope call was denied", recs[2].action.authorization.decision === "denied", true);

console.log("\nTAMPERING  (all must fail)");
let a = clone(2); a.action.authorization.decision = "allowed";
line("decision denied -> allowed", checkSig(a), false);
let b = clone(0); b.action.tool = "delete_database";
line("tool renamed", checkSig(b), false);
let c = clone(0); c.principal.human_id = "did:trail:org:evil-corp-0000";
line("principal swapped", checkSig(c), false);
let d = clone(0); d.agent.id = "did:trail:agent:someone-else-1111";
line("agent id swapped", checkSig(d), false);
let e = clone(0); e.verification.status = "blocked";
line("verification status flipped", checkSig(e), false);
let f = clone(0); f.data.authority_reason = "totally fine";
line("authority reason edited", checkSig(f), false);

console.log("\nWRONG KEY  (must fail)");
const other = generateKeyPair();
const { integrity, ...rest } = recs[0];
const sgn = { ...rest, data:{ ...rest.data } }; delete sgn.data.agent_proof;
line("verified with an unrelated key",
  verifyProof(sgn, recs[0].data.agent_proof, other.publicKeyBytes), false);

console.log("\nFORGED SCOPE GRANT  (must be rejected)");
const attacker = generateKeyPair();
const forged = issueScopeGrant(["search_docs","get_weather","delete_database"],
                               attacker.privateKeyBytes);
const r = verifyAuthority("delete_database", forged);
line("attacker self-signs a wider scope", r.proven, false);
console.log(`  reason: ${r.reason}`);

const selfDoc = {
  "@context":["https://www.w3.org/ns/credentials/v2","https://trailprotocol.org/ns/credentials/v1"],
  type:["VerifiableCredential","ScopeGrantCredential"],
  issuer: agentDid, validFrom, validUntil,
  credentialSubject:{ id: agentDid, authorizedTools:["search_docs","get_weather","delete_database"] },
};
const selfGrant = { ...selfDoc, proof: createProof(selfDoc, agentKeys.privateKeyBytes,
  `${agentDid}#key-1`, "assertionMethod") };
const rSelf = verifyAuthority("delete_database", selfGrant);
line("agent self-issues a wider scope (issuer=agent)", rSelf.proven, false);
console.log(`  reason: ${rSelf.reason}`);

console.log("\nDone.\n");
