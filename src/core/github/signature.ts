// GitHub webhook signature check: `X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of the raw body>`,
// compared in constant time.
import { createHmac, timingSafeEqual } from "node:crypto";

const HEADER = /^sha256=([0-9a-f]{64})$/;

/** True only for a well-formed header whose HMAC matches the raw body. */
export function verifySignature(secret: string, body: Buffer, header: string | readonly string[] | undefined): boolean {
  if (secret.length === 0 || typeof header !== "string") return false;
  const hex = HEADER.exec(header)?.[1];
  if (hex === undefined) return false;
  const expected = createHmac("sha256", secret).update(body).digest();
  return timingSafeEqual(Buffer.from(hex, "hex"), expected);
}

/** The header GitHub would send for this body; for tests and local tooling. */
export const signatureHeader = (secret: string, body: Buffer | string): string =>
  `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
