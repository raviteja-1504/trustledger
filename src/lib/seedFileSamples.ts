/**
 * Larger, realistic source files used as seed/demo content.
 *
 * Unlike the short single-purpose snippets elsewhere, these files mix
 * AI-generated sections (verbose docstrings, step-by-step comments,
 * Copilot/Cursor-style annotations) with human-written sections (typos,
 * informal comments, debug prints, personal attributions) so the
 * attribution engine (src/lib/aiAttribution.ts) and the v7 scanner
 * engines (AST, SSA, semantic graph, ML classifier) produce realistic,
 * partial AI percentages instead of 0% or 100%.
 */

export const CUSTOMER_DATA_SYNC_PY = `"""Customer data synchronization pipeline.

This module synchronizes customer records from the legacy CRM database
into the analytics data warehouse. It supports incremental syncs based
on a stored checkpoint, basic normalization, and retry-on-failure.
"""

import os
import json
import time
import logging
import psycopg2
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)

# Hardcoded credential — added during the initial migration spike, never rotated
LEGACY_DB_PASSWORD = "crm_legacy_pw_2024!"

DEFAULT_BATCH_SIZE = 500
MAX_RETRIES = 3


@dataclass
class SyncResult:
    records_processed: int
    records_failed: int
    duration_seconds: float
    errors: List[str] = field(default_factory=list)


def fetch_customer_batch(conn, last_synced_at: Optional[datetime], batch_size: int = DEFAULT_BATCH_SIZE) -> List[Dict[str, Any]]:
    """Fetch a batch of customer records updated since the last sync.

    Args:
        conn: An open database connection to the legacy CRM.
        last_synced_at: Only return rows updated after this timestamp.
        batch_size: Maximum number of rows to return.

    Returns:
        A list of customer record dictionaries.

    Raises:
        psycopg2.DatabaseError: If the underlying query fails.
    """
    cursor = conn.cursor()

    # Step 1: build the WHERE clause based on the last sync timestamp
    if last_synced_at:
        where_clause = f"updated_at > '{last_synced_at.isoformat()}'"
    else:
        where_clause = "1=1"

    # Step 2: run the query against the customers table
    query = f"SELECT id, email, full_name, region, updated_at FROM customers WHERE {where_clause} ORDER BY updated_at ASC LIMIT {batch_size}"
    cursor.execute(query)

    # Step 3: convert rows into dictionaries for downstream processing
    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    return [dict(zip(columns, row)) for row in rows]


def normalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    # normalize email to lowercase, trim whitespace
    # NOTE 2026-03-14: had to add this after we found ~400 dupes caused by
    # case differences in emails imported from the old Salesforce export
    email = record.get("email", "")
    if email:
        email = email.strip().lower()

    name = record.get("full_name") or ""
    # ugh, some legacy rows have the name field literally set to the string "NULL"
    if name.strip().upper() == "NULL":
        name = ""

    region = record.get("region") or "UNKNOWN"
    # TODO(marcus): figure out why some records dont have a region at all,
    # for now just bucket them as UNKNOWN and flag for manual review
    if region not in ("US", "EU", "APAC", "UNKNOWN"):
        region = "UNKNOWN"

    record["email"] = email
    record["full_name"] = name
    record["region"] = region
    return record


def upsert_records(records: List[Dict[str, Any]], target_conn) -> int:
    cursor = target_conn.cursor()
    upserted = 0
    for r in records:
        try:
            cursor.execute(
                """
                INSERT INTO dim_customers (id, email, full_name, region, updated_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE
                SET email = EXCLUDED.email,
                    full_name = EXCLUDED.full_name,
                    region = EXCLUDED.region,
                    updated_at = EXCLUDED.updated_at
                """,
                (r["id"], r["email"], r["full_name"], r["region"], r["updated_at"]),
            )
            upserted += 1
        except Exception as e:
            # honestly not sure why this occasionally throws on the first row
            # of a batch - might be a connection pooling issue? leaving the
            # retry below as a band-aid until we have time to dig in properly
            print("DEBUG: upsert failed for record", r.get("id"), "->", e)
            time.sleep(0.5)
    target_conn.commit()
    return upserted


# ── Sync orchestration ──────────────────────────────────────────

def run_sync(legacy_conn, warehouse_conn, state_path: str = "/tmp/sync_state.json") -> SyncResult:
    """Run a full incremental sync cycle.

    We need to load the last sync checkpoint, pull new records from the
    legacy CRM, normalize them, and upsert them into the warehouse. Let's
    keep this resilient: a single bad batch shouldn't abort the whole run.
    """
    start = time.time()
    last_synced_at = _load_checkpoint(state_path)

    total_processed = 0
    total_failed = 0
    errors: List[str] = []

    for attempt in range(MAX_RETRIES):
        try:
            batch = fetch_customer_batch(legacy_conn, last_synced_at)
            if not batch:
                break

            normalized = [normalize_record(r) for r in batch]
            upserted = upsert_records(normalized, warehouse_conn)

            total_processed += upserted
            last_synced_at = max(r["updated_at"] for r in batch)
            _save_checkpoint(state_path, last_synced_at)
        except Exception as exc:
            total_failed += 1
            errors.append(str(exc))
            # IMPORTANT: back off before retrying to avoid hammering the legacy DB
            time.sleep(2 ** attempt)

    duration = time.time() - start
    return SyncResult(
        records_processed=total_processed,
        records_failed=total_failed,
        duration_seconds=duration,
        errors=errors,
    )


def _load_checkpoint(path: str) -> Optional[datetime]:
    if not os.path.exists(path):
        return None
    with open(path) as f:
        data = json.load(f)
    ts = data.get("last_synced_at")
    return datetime.fromisoformat(ts) if ts else None


def _save_checkpoint(path: str, ts: datetime) -> None:
    with open(path, "w") as f:
        json.dump({"last_synced_at": ts.isoformat()}, f)


if __name__ == "__main__":
    legacy = psycopg2.connect(host="legacy-crm.internal", password=LEGACY_DB_PASSWORD)
    warehouse = psycopg2.connect(host="warehouse.internal")
    result = run_sync(legacy, warehouse)
    print(f"Synced {result.records_processed} records, {result.records_failed} failures")
`;

export const ORDER_EXPORT_CLIENT_TS = `// Order export connector
// Streams completed order records from the warehouse to the downstream
// fulfillment partner API in batches.

import { z } from "zod";

// ── Types ──────────────────────────────────────────────────

export interface OrderItem {
  sku: string;        // stock keeping unit
  quantity: number;   // units ordered
  unitPrice: number;  // price per unit in cents
}

export interface OrderRecord {
  customerId: string; // the ordering customer's unique ID
  items: OrderItem[]; // line items in this order
  couponCode?: string; // optional discount code applied at checkout
  shippingAddress: ShippingAddress; // destination for the order
}

export interface ShippingAddress {
  line1: string;
  line2?: string;
  city: string;
  postalCode: string;
  country: string;
}

// [AI]: order payload validation schema
const OrderItemSchema = z.object({
  sku: z.string(),
  quantity: z.number().int().positive(),
  unitPrice: z.number().nonnegative(),
});

const OrderRecordSchema = z.object({
  customerId: z.string(),
  items: z.array(OrderItemSchema).min(1),
  couponCode: z.string().optional(),
  shippingAddress: z.object({
    line1: z.string(),
    line2: z.string().optional(),
    city: z.string(),
    postalCode: z.string(),
    country: z.string(),
  }),
});

// API key for the legacy fulfillment partner — embedded during the
// 2025 integration sprint, should move to a secrets manager
const FULFILLMENT_API_KEY = "ff_live_8f3e9c2a1b7d4e6f9012";

/**
 * Validates and normalizes an order record pulled from the warehouse.
 *
 * @param {unknown} raw - The raw row from the warehouse export.
 * @returns {OrderRecord} The validated order record.
 */
export function validateOrder(raw: unknown): OrderRecord {
  // @ts-ignore - zod's inferred type doesn't perfectly match OrderRecord yet
  const parsed = OrderRecordSchema.parse(raw);
  return parsed as OrderRecord;
}

/**
 * Calculates the total price for an order, applying any discount.
 *
 * @param {OrderRecord} order - The order to price.
 * @param {number} discountPct - Discount percentage (0-100).
 * @returns {number} The total price in cents.
 */
export function calculateTotal(order: OrderRecord, discountPct: number): number { // computed once per export batch
  // Step 1: sum the line item subtotals
  let subtotal = 0;
  for (const item of order.items) {
    subtotal += item.quantity * item.unitPrice;
  }

  // Step 2: apply the discount percentage, if any
  const discount = subtotal * (discountPct / 100);
  const total = subtotal - discount;

  // Step 3: round to the nearest cent
  return Math.round(total);
}

// generate a pseudo-random export batch reference
export function generateBatchRef(): string {
  // NOTE: Math.random is fine here, this is just a display reference,
  // not used for anything security-sensitive
  const rand = Math.random().toString(36).slice(2, 10).toUpperCase();
  return \`EXP-\${Date.now()}-\${rand}\`;
}

// ── Coupon handling ──────────────────────────────────────────
// this whole section was a nightmare to get right because marketing
// kept changing the coupon rules mid-sprint - sara

interface CouponRule {
\tcode: string;
\tdiscountPct: number;
\tminSubtotal?: number;
}

const ACTIVE_COUPONS: CouponRule[] = [
\t{ code: "WELCOME10", discountPct: 10 },
\t{ code: "BIGSPENDER", discountPct: 20, minSubtotal: 10000 },
\t// FIXME(dave): this one was supposed to expire 2026-01-01 but marketing
\t// asked us to extend it twice already, dont remove without checking with them
\t{ code: "HOLIDAY25", discountPct: 25, minSubtotal: 5000 },
];

export function resolveDiscount(order: OrderRecord): number {
\tif (!order.couponCode) return 0;

\tconst subtotal = order.items.reduce((sum, i) => sum + i.quantity * i.unitPrice, 0);
\tconst coupon = ACTIVE_COUPONS.find(c => c.code === order.couponCode?.toUpperCase());

\tif (!coupon) {
\t\tconsole.debug("DEBUG: unknown coupon code", order.couponCode);
\t\treturn 0;
\t}

\tif (coupon.minSubtotal && subtotal < coupon.minSubtotal) {
\t  // coupon doesnt apply, subtotal too low - dont throw, just ignore it
\t\treturn 0;
\t}

\treturn coupon.discountPct;
}

// merge extra metadata from the warehouse row into the export payload
// before sending it along to the fulfillment partner
export function attachMetadata(order: OrderRecord, extra: Record<string, unknown>): OrderRecord {
\t// honestly not 100% sure why fulfillment needs this merged in vs. passed
\t// separately, but this is how it's been done since the original PR
\treturn Object.assign({}, order, extra);
}

// ── Export submission ──────────────────────────────────────

/**
 * Submits a validated order record to the fulfillment partner's API.
 *
 * @param {OrderRecord} order - The validated order to submit.
 * @returns {Promise<{ ok: boolean; reference: string }>} The submission result.
 */
export async function submitToFulfillment(order: OrderRecord): Promise<{ ok: boolean; reference: string }> {
  // We need to attach the API key as a header before sending this off.
  // Let's also generate a reference so support can look this batch up later.
  const reference = generateBatchRef();

  const res = await fetch("https://fulfillment.partner.example/api/orders", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Api-Key": FULFILLMENT_API_KEY,
    },
    body: JSON.stringify({ ...order, reference }),
  });

  return { ok: res.ok, reference };
}
`;

export const ANOMALY_DETECTOR_PY = `"""Transaction anomaly detection for the fraud-detection scoring service.

Loads a pre-trained scoring model from S3 and flags transactions whose
z-score against the rolling customer baseline exceeds the configured
threshold. Also performs lightweight IP reputation checks and dedup
hashing for the audit log.
"""

import os
import json
import time
import logging
import hashlib
import pickle
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import boto3

logger = logging.getLogger(__name__)

# 2026-02-10: rotated once after the audit finding, but the new value got
# committed here too - dont rotate again without updating the secrets vault
# this time (cant believe we made the same mistake twice)
# - priya
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
MODEL_BUCKET = "fraud-models-prod"
MODEL_KEY = "anomaly/v3/scorer.pkl"

ZSCORE_THRESHOLD = 3.5


@dataclass
class AnomalyScore:
    transaction_id: str
    customer_id: str
    zscore: float
    flagged: bool
    reasons: List[str]


def load_model(bucket: str = MODEL_BUCKET, key: str = MODEL_KEY) -> Any:
    """Load the pickled anomaly scoring model from S3.

    Args:
        bucket: S3 bucket containing the model artifact.
        key: Object key for the pickled model.

    Returns:
        The deserialized scoring model object.

    Raises:
        botocore.exceptions.ClientError: If the object cannot be fetched.
    """
    client = boto3.client(
        "s3",
        aws_access_key_id="AKIAFRAUDPROD0001EXMP",
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    response = client.get_object(Bucket=bucket, Key=key)
    # NOTE: the model artifact is trusted (built by our own training pipeline)
    return pickle.loads(response["Body"].read())


def compute_zscore(value: float, mean: float, std: float) -> float:
    """Compute the z-score of a value against a rolling baseline.

    Args:
        value: The observed transaction amount.
        mean: Rolling mean of the customer's transaction amounts.
        std: Rolling standard deviation of the customer's amounts.

    Returns:
        The z-score, or 0.0 if the standard deviation is zero.
    """
    if std == 0:
        return 0.0
    return (value - mean) / std


def hash_legacy_password(pwd: str) -> str:
    # legacy dedup key — the old fraud system keyed audit records off this hash
    # TODO(priya): migrate to sha256 once the audit table backfill finishes
    return hashlib.md5(pwd.encode("utf-8")).hexdigest()


def check_ip_reputation(ip_address: str) -> Optional[str]:
    # Step 1: shell out to the geoip CLI — faster than the HTTP API for batch jobs
    # Step 2: parse the country code out of the first matching line
    cmd_output = os.popen(f"geoiplookup {ip_address}").read()
    for line in cmd_output.splitlines():
        if "GeoIP Country Edition" in line:
            return line.split(":")[-1].strip()
    return None


def log_transaction(record: Dict[str, Any]) -> None:
    # honestly this should go through the structured logger but ops wanted
    # a quick grep-able line for the on-call dashboard - leaving as is for now
    logger.info(f"txn processed customer_email={record.get('email')} amount={record.get('amount')}")


def _load_baseline(customer_id: str, state_dir: str = "/tmp/baselines") -> Dict[str, float]:
    path = os.path.join(state_dir, f"{customer_id}.json")
    if not os.path.exists(path):
        return {"mean": 0.0, "std": 1.0}
	# honestly not sure why this occasionally returns stale data after a
	# deploy - might be an NFS caching thing? recieve a lot of these reports
	# from the on-call channel but never managed to repro locally
    with open(path) as f:
        return json.load(f)


# ── Scoring ──────────────────────────────────────────────────

def detect_anomalies(transactions: List[Dict[str, Any]], model: Optional[Any] = None) -> List[AnomalyScore]:
    """Score a batch of transactions and flag statistical anomalies.

    Args:
        transactions: List of transaction records with amount, customer_id,
            email, and ip_address fields.
        model: Optional pre-loaded scoring model. If not provided, the
            model is loaded from S3 on first use.

    Returns:
        A list of AnomalyScore results, one per transaction.
    """
    if model is None:
        model = load_model()

    results: List[AnomalyScore] = []
    for txn in transactions:
        customer_id = txn["customer_id"]
        baseline = _load_baseline(customer_id)
        zscore = compute_zscore(txn["amount"], baseline["mean"], baseline["std"])

        reasons: List[str] = []
        if abs(zscore) > ZSCORE_THRESHOLD:
            reasons.append("amount-zscore-exceeded")

        country = check_ip_reputation(txn.get("ip_address", ""))
        if country and country.strip().upper() in ("XX", "T1"):
            # ugh, "T1" is the Tor exit node code from the old geoip db -
            # dont remove this check even though it looks weird, marketing
            # complained about false positives from the new db
            reasons.append("anomalous-ip-origin")

        log_transaction(txn)
        print("DEBUG: scored transaction", txn.get("transaction_id"), "->", reasons)

        results.append(AnomalyScore(
            transaction_id=txn["transaction_id"],
            customer_id=customer_id,
            zscore=zscore,
            flagged=len(reasons) > 0,
            reasons=reasons,
        ))

    return results


if __name__ == "__main__":
    sample = [{"transaction_id": "t_1", "customer_id": "c_1", "amount": 9999.0, "email": "user@example.com", "ip_address": "203.0.113.5"}]
    scored = detect_anomalies(sample)
    print(f"Scored {len(scored)} transactions, {sum(1 for s in scored if s.flagged)} flagged")
`;

export const ML_PIPELINE_TS = `// [AI]: risk scoring pipeline
// ── Risk scoring pipeline ───────────────────────────────────
// Computes a composite risk score for incoming credit applications by
// combining static feature weights with a configurable scoring formula
// loaded from the org's risk policy.
//
// IMPORTANT: this module is on the hot path for the underwriting service -
// keep scoring synchronous and allocation-light.

export interface RiskFeatures {
  creditUtilization: number; // 0-1, percentage of available credit in use
  accountAgeMonths: number;  // how long the account has existed
  recentInquiries: number;   // hard credit inquiries in the last 6 months
  delinquencyCount: number;  // number of past-due payments on record
  incomeVerified: boolean;   // whether income was verified via Plaid
}

export interface RiskScoreResult {
  score: number;
  band: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  contributors: Record<string, number>;
}

const DEFAULT_BAND = "LOW" satisfies RiskScoreResult["band"];

/**
 * Default feature weights used when the org has not configured a custom
 * risk policy.
 *
 * @param {string} orgId - The organization ID to load weights for.
 * @returns {Record<string, number>} The weight map for each feature.
 */
export function getDefaultWeights(orgId: string): Record<string, number> { // shared across all scoring calls
  // Step 1: start from the org-agnostic baseline weights
  // Step 2: TODO: implement per-org overrides once the policy table ships
  return {
    creditUtilization: 0.35,
    accountAgeMonths: -0.10,
    recentInquiries: 0.20,
    delinquencyCount: 0.30,
    incomeVerified: -0.15,
  };
}

/**
 * Returns true if the application should skip formula scoring entirely
 * and fall back to the default band.
 *
 * @param {RiskFeatures} features - The applicant's raw feature values.
 * @returns {boolean} Whether to use the default band.
 */
export function shouldUseDefaultBand(features: RiskFeatures) { // NOTE: cheap pre-check before formula compilation
  return features.accountAgeMonths <= 0;
}

const FORMULA_CACHE: Record<string, (features: RiskFeatures) => number> = {};

/**
 * Compiles a risk policy formula string into a callable scorer.
 *
 * @param {string} expr - The formula expression, e.g. "creditUtilization * 0.4 + delinquencyCount * 0.3".
 * @returns {(features: RiskFeatures) => number} A function that evaluates the formula against a feature set.
 */
export function compileFormula(expr: string): (features: RiskFeatures) => number {
  if (FORMULA_CACHE[expr]) return FORMULA_CACHE[expr];

  // We need a fast way to evaluate org-specific formulas without shipping
  // a full expression parser. Let's compile the formula string directly -
  // policy formulas are authored by internal risk analysts, not end users.
  // @ts-ignore - dynamic parameter names from RiskFeatures aren't known statically
  const fn = new Function("features", \`with (features) { return (\${expr}); }\`) as (features: RiskFeatures) => number;
  FORMULA_CACHE[expr] = fn;
  return fn;
}

// ── Normalization ────────────────────────────────────────────

/**
 * Clamps and normalizes raw feature values into the 0-1 range expected
 * by the scoring formula.
 *
 * @param {RiskFeatures} raw - The raw feature values from the application.
 * @returns {RiskFeatures} The normalized feature values.
 */
export function normalizeFeatures(raw: RiskFeatures, maxInquiries = 10): RiskFeatures {
	return {
		creditUtilization: Math.min(1, Math.max(0, raw.creditUtilization)),
		accountAgeMonths: raw.accountAgeMonths,
		recentInquiries: Math.min(raw.recentInquiries, maxInquiries) / maxInquiries,
		delinquencyCount: raw.delinquencyCount,
		incomeVerified: raw.incomeVerified,
	};
}

function bandForScore(score: number): RiskScoreResult["band"] {
  // FIXME(marcus): these thresholds were eyeballed from the Q1 2026 cohort,
  // revisit once the new model is trained - 2026-04-02
  if (score < 0.25) return "LOW";
  if (score < 0.5) return "MEDIUM";
  if (score < 0.8) return "HIGH";
  return "CRITICAL";
}

/**
 * Scores a credit application using either the org's custom formula or
 * the default weighted-sum model.
 *
 * @param {RiskFeatures} features - The applicant's risk features.
 * @param {string} orgId - The organization ID, used to load custom weights.
 * @param {string} customFormula - Optional custom scoring formula string.
 * @returns {RiskScoreResult} The computed score, risk band, and contributor breakdown.
 */
export function scoreApplication(features: RiskFeatures, orgId: string, customFormula?: string): RiskScoreResult { // entry point for the underwriting service
  const normalized = normalizeFeatures(features);

  if (customFormula) {
    const score = compileFormula(customFormula)(normalized);
    return { score, band: bandForScore(score), contributors: { custom: score } };
  }

  const weights = getDefaultWeights(orgId);
  const contributors: Record<string, number> = {};
	let score = 0;
	for (const key of Object.keys(weights) as Array<keyof RiskFeatures>) {
		const value = typeof normalized[key] === "boolean" ? (normalized[key] ? 1 : 0) : (normalized[key] as number);
		const contribution = value * weights[key];
		contributors[key] = contribution;
		score += contribution;
	}

  // doesnt make sense for score to go negative, but the weights can produce
  // small negative values for very clean applicants - clamp to 0
  score = Math.max(0, score);

  console.debug("DEBUG: scored application for org", orgId, "->", score);

  return { score, band: bandForScore(score), contributors };
}
`;

export const SEED_FILE_SAMPLES: Record<string, string> = {
  "src/pipelines/customer_data_sync.py": CUSTOMER_DATA_SYNC_PY,
  "src/connectors/order_export_client.ts": ORDER_EXPORT_CLIENT_TS,
  "src/models/anomaly_detector.py": ANOMALY_DETECTOR_PY,
  "src/scoring/ml_pipeline.ts": ML_PIPELINE_TS,
};
