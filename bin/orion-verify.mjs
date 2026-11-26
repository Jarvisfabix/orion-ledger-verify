#!/usr/bin/env node
/**
 * ORION Ledger Verify — Independent Open-Source Verifier (MIT License)
 * Author: AI Synapse Technologies, S.L.U. (https://aisynapse.tech | https://orion.aisynapse.tech)
 *
 * Verifies cryptographic integrity of ECDSA (P-256) + SHA-256 hash-chained AI audit receipts
 * without requiring vendor access, aligned with EU AI Act Art. 12, Art. 19(1), Art. 26(6) & Art. 73.
 * Zero external dependencies — uses only Node.js built-in `node:crypto` and `node:fs`.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
}

function sha256Hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function generateSample(outPath) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const rawEvents = [
    {
      seq: 1,
      timestampUtc: '2026-11-25T09:14:02.411Z',
      tenantId: 'gov_cat_social_04',
      aiSystemId: 'ai_grant_assist_v2',
      riskTier: 'ANNEX_III_HIGH_RISK',
      friaRef: 'FRIA-2026-0118',
      policyBundleHash: sha256Hex('pb_v3.4_aapp'),
      promptHashSha256: sha256Hex('redacted_prompt_001'),
      verdict: 'AUTHORIZED',
      piiRedactions: 3,
      modelRouted: 'mistral-large-eu-sovereign',
      art50Disclosed: true,
    },
    {
      seq: 2,
      timestampUtc: '2026-11-25T09:16:48.902Z',
      tenantId: 'mun_bcn_housing_02',
      aiSystemId: 'ai_housing_ranker_v1',
      riskTier: 'ANNEX_III_HIGH_RISK',
      friaRef: 'FRIA-2025-0082-EXPIRED',
      policyBundleHash: sha256Hex('pb_v3.4_aapp'),
      promptHashSha256: sha256Hex('blocked_before_gate_07'),
      verdict: 'BLOCKED_GATE_03_FRIA_EXPIRED',
      piiRedactions: 0,
      modelRouted: 'NONE_FAIL_CLOSED',
      art50Disclosed: false,
    },
    {
      seq: 3,
      timestampUtc: '2026-11-25T09:21:11.150Z',
      tenantId: 'fin_eu_retail_bank_09',
      aiSystemId: 'ai_credit_copilot_v3',
      riskTier: 'ANNEX_III_5B_CREDIT',
      friaRef: 'FRIA-2026-0412',
      policyBundleHash: sha256Hex('pb_v4.1_dora_banking'),
      promptHashSha256: sha256Hex('blocked_prompt_injection'),
      verdict: 'BLOCKED_GATE_06_ADVERSARIAL',
      piiRedactions: 0,
      modelRouted: 'NONE_FAIL_CLOSED',
      art50Disclosed: false,
    },
  ];

  let prevHash = '0'.repeat(64);
  const receipts = rawEvents.map((payload) => {
    const bodyToHash = canonicalJson({ prevHash, payload });
    const entryHash = sha256Hex(bodyToHash);
    const signer = crypto.createSign('SHA256');
    signer.update(entryHash, 'utf8');
    signer.end();
    const signatureBase64 = signer.sign(privateKey, 'base64');
    const receipt = { prevHash, payload, entryHash, signatureBase64 };
    prevHash = entryHash;
    return receipt;
  });

  const bundle = {
    schema: 'orion-audit-ledger/v1',
    standard: 'EU AI Act Art. 12, Art. 19(1), Art. 26(6) & Art. 73',
    signatureAlgorithm: 'ECDSA-P256-SHA256',
    issuer: 'AI Synapse Technologies Reference Sample (https://orion.aisynapse.tech)',
    deployerPublicKeyPem: publicKey,
    receipts,
  };

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(bundle, null, 2) + '\n', 'utf8');
  console.log(`[OK] Generated signed sample Art. 12 ledger bundle (${receipts.length} receipts) -> ${outPath}`);
}

function verifyBundle(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const bundle = JSON.parse(raw);
  const { deployerPublicKeyPem, receipts } = bundle;

  if (!deployerPublicKeyPem || !Array.isArray(receipts) || receipts.length === 0) {
    console.error('[FAIL] Invalid ledger bundle structure.');
    process.exit(1);
  }

  let expectedPrev = '0'.repeat(64);
  let failures = 0;

  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    const computedHash = sha256Hex(canonicalJson({ prevHash: r.prevHash, payload: r.payload }));
    const chainOk = r.prevHash === expectedPrev;
    const hashOk = computedHash === r.entryHash;

    const verifier = crypto.createVerify('SHA256');
    verifier.update(r.entryHash, 'utf8');
    verifier.end();
    const sigOk = verifier.verify(deployerPublicKeyPem, r.signatureBase64, 'base64');

    const ok = chainOk && hashOk && sigOk;
    console.log(
      `${ok ? '[PASS]' : '[FAIL]'} Receipt #${r.payload?.seq ?? i + 1} | verdict=${r.payload?.verdict} | chain=${chainOk} | sha256=${hashOk} | ecdsa=${sigOk}`
    );
    if (!ok) failures++;
    expectedPrev = r.entryHash;
  }

  if (failures > 0) {
    console.error(`\n[TAMPER DETECTED] ${failures} receipt(s) failed independent cryptographic verification.`);
    process.exit(2);
  }

  console.log(`\n[VERIFIED] All ${receipts.length} receipts passed SHA-256 chain & ECDSA P-256 verification (vendor-independent).`);
}

const args = process.argv.slice(2);
if (args[0] === '--generate-sample' && args[1]) {
  generateSample(args[1]);
} else if (args[0]) {
  verifyBundle(args[0]);
} else {
  console.log('Usage:\n  node bin/orion-verify.mjs <ledger-bundle.json>\n  node bin/orion-verify.mjs --generate-sample <out.json>');
  process.exit(1);
}
