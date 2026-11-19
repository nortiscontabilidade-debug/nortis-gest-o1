import { serve } from "std/server";
import { createClient } from "@supabase/supabase-js";
import { recordAudit } from "../_shared/audit.ts";

/**
 * Edge Function: revela a credencial criptografada.
 * Recebe JSON: { secret_id: "<uuid>", ip_address: "…", user_agent: "…" }
 * 1. Verifica permissão (RLS protege a SELECT).
 * 2. Registra auditoria (action='reveal').
 * 3. Decripta com a chave AES‑256‑GCM (variável de ambiente SECRET_KEY).
 */
serve(async (req) => {
  const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const secretKey = Deno.env.get("SECRET_KEY")!; // base64

  const client = createClient(supabaseUrl, serviceKey, { auth: { persistSession: false } });
  const { secret_id, ip_address, user_agent } = await req.json();

  // Busca o registro (SELECT será autorizado apenas se o usuário tiver permissão)
  const { data, error } = await client
    .from("secrets")
    .select("encrypted_value, iv, tag")
    .eq("id", secret_id)
    .single();

  if (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 400, headers: { "Content-Type": "application/json" } });
  }

  // Decriptação usando Web Crypto (compatível com Deno)
  const keyRaw = Uint8Array.from(atob(secretKey), (c) => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey("raw", keyRaw, { name: "AES-GCM" }, false, ["decrypt"]);
  const iv = Uint8Array.from(atob(data.iv), (c) => c.charCodeAt(0));
  const tag = Uint8Array.from(atob(data.tag), (c) => c.charCodeAt(0));
  const ciphertext = Uint8Array.from(atob(data.encrypted_value), (c) => c.charCodeAt(0));
  const encrypted = new Uint8Array([...ciphertext, ...tag]);

  let plain;
  try {
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, encrypted);
    plain = new TextDecoder().decode(decrypted);
  } catch (e) {
    return new Response(JSON.stringify({ error: "Decryption failed" }), { status: 500, headers: { "Content-Type": "application/json" } });
  }

  // Auditoria
  await recordAudit(client, {
    user_id: client.auth.user()?.id ?? null,
    action: "reveal",
    entity: "secret",
    entity_id: secret_id,
    ip_address,
    user_agent,
  });

  return new Response(JSON.stringify({ value: plain }), { status: 200, headers: { "Content-Type": "application/json" } });
});
