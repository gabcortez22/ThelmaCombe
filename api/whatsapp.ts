import { createHmac, timingSafeEqual } from "node:crypto";

const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;
const APP_SECRET = process.env.WHATSAPP_APP_SECRET;

// GET: Meta verifies the callback URL by sending hub.* query params.
export function GET(request: Request): Response {
  const params = new URL(request.url).searchParams;
  const mode = params.get("hub.mode");
  const token = params.get("hub.verify_token");
  const challenge = params.get("hub.challenge");

  if (VERIFY_TOKEN && mode === "subscribe" && token === VERIFY_TOKEN && challenge) {
    return new Response(challenge, { status: 200 });
  }
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

  if (!validSignature(rawBody, request.headers.get("x-hub-signature-256"))) {
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
        // TODO: bot logic goes here. Route by phoneNumberId if you add more numbers.
        console.log("message", {
          phoneNumberId,
          from: message.from,
          type: message.type,
          text: message.text?.body,
          id: message.id,
        });
      }
      for (const status of value.statuses ?? []) {
        console.log("status", { phoneNumberId, id: status.id, status: status.status });
      }
    }
  }

  // Always answer 200 quickly so Meta does not retry.
  return new Response("OK", { status: 200 });
}
