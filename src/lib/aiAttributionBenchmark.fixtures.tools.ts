/**
 * Labeled per-tool fixture corpus for the AI-attribution engine's first-ever
 * per-tool quality gate (see `runToolAttributionBenchmark` in
 * `aiAttributionBenchmark.ts` and `__tests__/lib/aiAttributionBenchmark.test.ts`).
 *
 * Unlike `aiAttributionBenchmark.fixtures.ts` (binary ai/human, n=10), this
 * checks whether `attributeCode()`'s predicted `model` field identifies the
 * correct TOOL -- something that had zero validation anywhere in this
 * codebase before this file. Each sample is freshly authored to combine
 * multiple of that model's real positive signals from `aiAttribution.ts`
 * (not just one, since a single weak signal shouldn't be expected to win
 * outright) so this is a genuine "does the combined-signal design work"
 * check, not a trivial single-pattern echo test.
 *
 * Deliberately small (n=10) and skips Tabnine entirely -- its own code
 * comment in aiAttribution.ts already says its signals are "hard to
 * distinguish from human code," so a synthetic fixture there would be
 * closer to teaching to the test than a real quality signal.
 *
 * Gemini and CodeWhisperer samples specifically avoid relying on their
 * bare-import-only signals (which now require a corroborating signal —
 * see the `requiresCoSignal` hardening in aiAttribution.ts) and instead
 * combine genuine usage/style signals, proving the hardening still allows
 * real detection rather than just suppressing false positives.
 */

import type { AIModel } from "./aiAttribution";

export interface ToolBenchmarkSample {
  id:            string;
  expectedModel: AIModel;
  language:      string;
  content:       string;
}

export const TOOL_BENCHMARK_SAMPLES: ToolBenchmarkSample[] = [
  // ── GitHub Copilot ──────────────────────────────────────────────────────
  {
    id: "copilot-jsdoc-tsignore",
    expectedModel: "github-copilot",
    language: "typescript",
    content: `/**
 * @param {string} userId - The unique identifier for the user
 * @param {number} retryCount - The number of retries to attempt
 */
function fetchUserProfile(userId, retryCount) { // handleRequest
  // @ts-ignore
  const legacyClient = getLegacyClient();

  interface UserProfile {
    id: string; // unique
    name: string; // display
  }

  return legacyClient.load(userId, retryCount);
}`,
  },
  {
    id: "copilot-displayname-todo",
    expectedModel: "github-copilot",
    language: "typescript",
    content: `function UserAvatar(props) {
  // NOTE: Falls back to initials when no avatar URL is provided
  // TODO: add error handling for broken image URLs
  return renderAvatar(props);
}
UserAvatar.displayName = "UserAvatar";

interface AvatarProps {
  url: string; // optional
  size: number; // pixels
}`,
  },

  // ── ChatGPT ──────────────────────────────────────────────────────────────
  {
    id: "chatgpt-docstring-steps",
    expectedModel: "chatgpt",
    language: "python",
    content: `def calculate_discount(price, discount_percent):
    """
    Calculates the discounted price for a given item, including validation
    of the supplied inputs before the discount amount is applied.

    Args:
        price: The original price of the item.
        discount_percent: The discount percentage to apply.

    Returns:
        The final price after applying the discount.
    """
    # Step 1: Validate the input values
    if price < 0 or discount_percent < 0:
        raise ValueError("Invalid input")

    # This implementation assumes discount_percent is between 0 and 100
    discount_amount = price * (discount_percent / 100)
    return price - discount_amount


if __name__ == "__main__":
    print(calculate_discount(100, 20))`,
  },
  {
    id: "chatgpt-repl-narrative",
    expectedModel: "chatgpt",
    language: "python",
    content: `def normalize_email(email):
    """
    Normalizes an email address for consistent storage and comparison
    across the application, handling common formatting differences.

    Example:
        >>> normalize_email("User@Example.COM")
        'user@example.com'
    """
    # Note: This trims whitespace before lowercasing the address
    email = email.strip()

    # First, we lowercase the domain portion
    # Then, we lowercase the local portion as well
    return email.lower()`,
  },

  // ── Gemini ───────────────────────────────────────────────────────────────
  {
    id: "gemini-dataclass-docstring",
    expectedModel: "gemini",
    language: "python",
    content: `from typing import Optional, List, Dict


@dataclass
class UserRecord:
    id: str
    name: str
    email: Optional[str] = None


def find_active_users(status: str, limit: int, offset: int) -> List[UserRecord]:
    """Retrieves active user records matching the given status.

    Args:
        status: The status value to filter users by.
        limit: Maximum number of records to return.
        offset: Number of records to skip before returning results.

    Returns:
        A list of matching UserRecord instances.
    """
    return query_users(status, limit, offset)`,
  },
  {
    id: "gemini-pydantic-typed",
    expectedModel: "gemini",
    language: "python",
    content: `from pydantic import BaseModel
from typing import Optional, List, Dict


class OrderRequest(BaseModel):
    customer_id: str
    items: List[str]
    notes: Optional[str] = None


def process_order(request: OrderRequest, priority: bool, retries: int) -> Dict:
    """Processes an incoming order request and returns a status payload.

    Args:
        request: The validated order request payload.
        priority: Whether this order should be expedited.
        retries: Number of retry attempts allowed on failure.

    Returns:
        A dictionary describing the processing outcome.
    """
    return submit_order(request, priority, retries)`,
  },

  // ── Claude ───────────────────────────────────────────────────────────────
  {
    id: "claude-sections-satisfies",
    expectedModel: "claude",
    language: "typescript",
    content: `// ─── Order validation ──────────────────────────────────────────────────

// We need to check that the cart isn't empty before proceeding
function validateCart(cart: Cart) {
  // IMPORTANT: Empty carts must never reach the payment step
  if (cart.items.length === 0) {
    throw new Error("Cart is empty");
  }
}

// ─── Types ──────────────────────────────────────────────────────────────

const defaultConfig = {
  retries: 3,
  timeout: 5000,
} satisfies RetryConfig;`,
  },
  {
    id: "claude-sections-python",
    expectedModel: "claude",
    language: "python",
    content: `# ─── Retry helpers ──────────────────────────────────────────────────────

# Let's keep the backoff calculation isolated so it's easy to unit test
def compute_backoff(attempt, base_delay):
    # NOTE: Capped at 30 seconds to avoid runaway wait times in worst case
    delay = base_delay * (2 ** attempt)
    return min(delay, 30)


# ─── Constants ───────────────────────────────────────────────────────────

MAX_RETRIES = 5`,
  },

  // ── Cursor ───────────────────────────────────────────────────────────────
  {
    id: "cursor-trpc-zod",
    expectedModel: "cursor",
    language: "typescript",
    content: `// File: src/server/routers/user.ts

// @cursor-generated
import { z } from "zod";

export const userRouter = createTRPCRouter({
  getById: publicProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => {
      return db.user.findUnique({ where: { id: input.id } });
    }),
});`,
  },

  // ── AWS CodeWhisperer ────────────────────────────────────────────────────
  // Combines the (now gated) bare boto3 import with genuine ungated usage
  // signals -- proving the co-signal hardening still lets real AWS-authored
  // code through rather than only ever suppressing it.
  {
    id: "codewhisperer-lambda-handler",
    expectedModel: "codewhisperer",
    language: "python",
    content: `import boto3
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    s3 = boto3.client("s3")
    queue_arn = "arn:aws:sqs:us-east-1:123456789012:my-queue"
    try:
        s3.get_object(Bucket="my-app-bucket", Key=event["key"])
    except ClientError as error:
        raise error
    return {"statusCode": 200, "queueArn": queue_arn}`,
  },
];
