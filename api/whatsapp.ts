import { createHmac, timingSafeEqual } from "node:crypto";

const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;
const APP_SECRET = process.env.WHATSAPP_APP_SECRET;
const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
const API_VERSION = process.env.WHATSAPP_API_VERSION ?? "v27.0";

const AUTO_REPLY =
  "¡Hola! Gracias por escribir a Thelma Combe. Recibimos tu mensaje y te responderemos muy pronto.";

// Sends a plain text reply. Free-form text only works inside the 24h window
// opened by the customer's message, which is exactly our case.
async function sendText(phoneNumberId: string, to: string, body: string): Promise<void> {
  if (!ACCESS_TOKEN) {
    console.warn("auto-reply skipped: WHATSAPP_ACCESS_TOKEN is not set");
    return;
  }
  const res = await fetch(`https://graph.facebook.com/${API_VERSION}/${phoneNumberId}/messages`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ACCESS_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      messaging_product: "whatsapp",
      to,
      type: "text",
      text: { body },
    }),
  });
  if (!res.ok) {
    console.error("auto-reply failed", { status: res.status, body: await res.text() });
  } else {
    console.log("auto-reply sent", { to, phoneNumberId });
  }
}

// GET: Meta verifies the callback URL by sending hub.* query params.
export function GET(request: Request): Response {
  const params = new URL(request.url).searchParams;
  const mode = params.get("hub.mode");
  const token = params.get("hub.verify_token");
  const challenge = params.get("hub.challenge");

  if (VERIFY_TOKEN && mode === "subscribe" && token === VERIFY_TOKEN && challenge) {
    return new Response(challenge, { status: 200 });
  }
  console.warn("webhook verification rejected", { mode, hasVerifyToken: Boolean(VERIFY_TOKEN) });
  return new Response("Forbidden", { status: 403 });
}

function validSignature(rawBody: string, header: string | null): boolean {
  if (!APP_SECRET || !header?.startsWith("sha256=")) return false;
  const expected = createHmac("sha256", APP_SECRET).update(rawBody).digest();
  const received = Buffer.from(header.slice("sha256=".length), "hex");
  return received.length === expected.length && timingSafeEqual(received, expected);
}

// POST: incoming messages and delivery statuses.
export async function POST(request: Request): Promise<Response> {
  const rawBody = await request.text();

  console.log("webhook POST received", { bytes: rawBody.length });

  if (!validSignature(rawBody, request.headers.get("x-hub-signature-256"))) {
    console.warn("webhook rejected: invalid or missing signature", {
      hasAppSecret: Boolean(APP_SECRET),
      hasSignatureHeader: Boolean(request.headers.get("x-hub-signature-256")),
    });
    return new Response("Invalid signature", { status: 401 });
  }

  let payload: any;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return new Response("Bad request", { status: 400 });
  }

  for (const entry of payload?.entry ?? []) {
    for (const change of entry?.changes ?? []) {
      const value = change?.value;
      if (!value) continue;
      const phoneNumberId = value.metadata?.phone_number_id;

      for (const message of value.messages ?? []) {
        console.log("message", {
          phoneNumberId,
          from: message.from,
          type: message.type,
          text: message.text?.body,
          id: message.id,
        });
        // Simple auto-reply to every inbound message from a customer.
        if (phoneNumberId && message.from) {
          try {
            await sendText(phoneNumberId, message.from, AUTO_REPLY);
          } catch (err) {
            console.error("auto-reply error", err);
          }
        }
      }
      for (const status of value.statuses ?? []) {
        console.log("status", { phoneNumberId, id: status.id, status: status.status });
      }
    }
  }

  // Always answer 200 quickly so Meta does not retry.
  return new Response("OK", { status: 200 });
}
