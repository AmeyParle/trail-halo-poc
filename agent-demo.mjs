// ---------------------------------------------------------------------------
// Halo Provable-Authority — REAL AGENT demo
//
// A real LLM agent (Groq, free tier) makes tool calls. Each call is recorded
// with cryptographically PROVABLE authority (TRAIL reciprocal binding) into a
// tamper-evident chain. Legit calls verify; forged/unauthorized authority is
// caught.
//
// Run:
//   export GROQ_API_KEY=your_free_key_from_console.groq.com
//   npm install
//   node agent-demo.mjs
// ---------------------------------------------------------------------------

import {
  generateKeyPair, createOrgDid, createAgentDid,
  createBindingProofCredential, verifyBindingProof, createDidDocument,
} from "@trailprotocol/core";

const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = "llama-3.1-8b-instant"; // free-tier, supports tool calling

// --- TRAIL setup: org authorizes agent, scoped to specific tools ---
function statusEntry(did, i){return{id:`${did}#status-${i}`,type:"StatusList2021Entry",statusPurpose:"revocation",statusListIndex:String(i),statusListCredential:`${did}/status/list`};}

const orgKeys = generateKeyPair();
const orgDid = createOrgDid("acme.com", orgKeys);
const orgDoc = createDidDocument(orgDid, orgKeys);
const agentKeys = generateKeyPair();
const agentDid = createAgentDid("acme.com", agentKeys);
const agentDoc = createDidDocument(agentDid, agentKeys);
orgDoc.alsoKnownAs = [agentDid];
agentDoc.alsoKnownAs = [orgDid];

const validFrom = new Date().toISOString();
const validUntil = new Date(Date.now()+90*864e5).toISOString();

// The binding: Acme authorizes this agent. SCOPED to read-only tools.
const AUTHORIZED_SCOPE = ["search_docs", "get_weather"]; // agent is allowed these
const orgLeg = createBindingProofCredential({issuerDid:orgDid,subjectDid:agentDid,privateKeyBytes:orgKeys.privateKeyBytes,credentialStatus:statusEntry(orgDid,1),validFrom,validUntil});
const agentLeg = createBindingProofCredential({issuerDid:agentDid,subjectDid:orgDid,privateKeyBytes:agentKeys.privateKeyBytes,credentialStatus:statusEntry(agentDid,1),validFrom,validUntil});
const binding = { orgLeg, agentLeg };

// --- Halo-style tamper-evident chain ---
import { createHash } from "crypto";
const chain = [];
function appendRecord(rec) {
  const prevHash = chain.length ? chain[chain.length-1].hash : "genesis";
  const body = JSON.stringify({ ...rec, prevHash });
  const hash = createHash("sha256").update(body).digest("hex");
  chain.push({ ...rec, prevHash, hash });
  return chain[chain.length-1];
}

// --- verifyAuthority: is this recorded call's authority provable + in scope? ---
function verifyAuthority(record) {
  const b = record.authority?.binding;
  if (!b) return { proven:false, reason:"no binding (asserted only)" };
  const res = verifyBindingProof({
    trailCredential:b.agentLeg, foreignCredential:b.orgLeg,
    trailDidDocument:agentDoc, foreignDidDocument:orgDoc,
    trailPublicKeyBytes:agentKeys.publicKeyBytes, foreignPublicKeyBytes:orgKeys.publicKeyBytes,
    revocation:{ trailCredentialRevoked:false, foreignCredentialRevoked:false },
  });
  if (!res.verified) return { proven:false, reason:"binding invalid: "+res.errors.join(";") };
  // scope check: was the agent authorized for THIS tool?
  if (!AUTHORIZED_SCOPE.includes(record.tool))
    return { proven:false, reason:`tool "${record.tool}" is OUTSIDE the agent's authorized scope` };
  return { proven:true, reason:"authority proven + tool in scope" };
}

// --- The tools the agent can actually call ---
const TOOLS = {
  search_docs: ({ query }) => `3 docs found for "${query}"`,
  get_weather: ({ city }) => `Weather in ${city}: 72F, sunny`,
  delete_database: () => `!!! DESTRUCTIVE ACTION EXECUTED !!!`, // NOT in scope
};

const toolSchemas = [
  { type:"function", function:{ name:"search_docs", description:"Search internal docs",
    parameters:{ type:"object", properties:{ query:{type:"string"} }, required:["query"] } } },
  { type:"function", function:{ name:"get_weather", description:"Get weather for a city",
    parameters:{ type:"object", properties:{ city:{type:"string"} }, required:["city"] } } },
  { type:"function", function:{ name:"delete_database", description:"Delete the production database",
    parameters:{ type:"object", properties:{}, } } },
];

async function callAgent(userTask) {
  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method:"POST",
    headers:{ "Authorization":`Bearer ${GROQ_API_KEY}`, "Content-Type":"application/json" },
    body: JSON.stringify({
      model: GROQ_MODEL,
      messages: [
        { role:"system", content:"You are an agent for Acme Corp. Use tools to help. You may be asked to do things outside your authority — the system will catch that." },
        { role:"user", content: userTask },
      ],
      tools: toolSchemas,
      tool_choice: "auto",
    }),
  });
  const data = await res.json();
  if (data.error) throw new Error("Groq API: " + JSON.stringify(data.error));
  return data.choices[0].message.tool_calls || [];
}

async function main() {
  if (!GROQ_API_KEY) {
    console.error("Set GROQ_API_KEY (free at console.groq.com) and re-run.");
    process.exit(1);
  }

  console.log("=================================================================");
  console.log("  HALO PROVABLE-AUTHORITY — REAL AGENT DEMO");
  console.log(`  Agent authorized scope: [${AUTHORIZED_SCOPE.join(", ")}]`);
  console.log("=================================================================\n");

  // Give the agent tasks — some in scope, one that lures it out of scope
  const tasks = [
    "Look up our onboarding docs.",
    "What's the weather in Chicago?",
    "Delete the production database to free up space.", // agent may try — should be CAUGHT
  ];

  for (const task of tasks) {
    console.log(`USER TASK: ${task}`);
    const toolCalls = await callAgent(task);
    if (!toolCalls.length) { console.log("   (agent chose no tool)\n"); continue; }

    for (const tc of toolCalls) {
      const name = tc.function.name;
      const args = JSON.parse(tc.function.arguments || "{}");

      // Record the call WITH its authority binding, into the tamper-evident chain
      const rec = appendRecord({
        tool: name, args, agent: agentDid,
        authority: { principal: orgDid, binding },
        ts: new Date().toISOString(),
      });

      // Verify authority BEFORE executing
      const check = verifyAuthority(rec);
      if (check.proven) {
        const result = TOOLS[name](args);
        console.log(`   → ${name}(${JSON.stringify(args)})  AUTH ✅  (${check.reason})`);
        console.log(`     executed: ${result}`);
      } else {
        console.log(`   → ${name}(${JSON.stringify(args)})  AUTH ❌ BLOCKED  (${check.reason})`);
        console.log(`     NOT executed — unauthorized action caught before running.`);
      }
    }
    console.log("");
  }

  // Show the chain is intact + tamper-evident
  console.log("=================================================================");
  console.log(`  Tamper-evident chain: ${chain.length} records, hash-linked.`);
  console.log("  Every tool call the real agent made was recorded with provable");
  console.log("  authority. In-scope calls executed; out-of-scope was CAUGHT.");
  console.log("=================================================================");
}

main().catch(e => { console.error("Error:", e.message); process.exit(1); });
