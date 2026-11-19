import { serve } from "std/server";
import { createClient } from "@supabase/supabase-js";
import { recordAudit } from "../_shared/audit.ts";

/**
 * Edge Function: registra tentativas de login (sucesso ou falha).
 * Espera um payload JSON:
 * {
 *   "event": "login",
 *   "data": {
 *     "user_id": "<uuid>",
 *     "ip_address": "1.2.3.4",
 *     "user_agent": "Mozilla/…",
 *     "success": true
 *   }
 * }
 */
serve(async (req) => {
  const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const supabase = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false },
  });

  const { event, data } = await req.json();
  if (event !== "login" || !data) {
    return new Response(JSON.stringify({ error: "Invalid payload" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const { user_id, ip_address, user_agent, success } = data;
  const { error } = await supabase.from("login_audit").insert({
    user_id,
    ip_address,
    user_agent,
    success,
    created_at: new Date().toISOString(),
  });

  if (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Opcional: registrar também na audit_log genérica
  await recordAudit(supabase, {
    user_id,
    action: success ? "login_success" : "login_failure",
    entity: "auth",
    entity_id: null,
    ip_address,
    user_agent,
  });

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
});
