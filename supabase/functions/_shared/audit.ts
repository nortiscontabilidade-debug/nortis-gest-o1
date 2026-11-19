import { SupabaseClient } from "@supabase/supabase-js";

/**
 * Helper to insert a row into the generic audit_log table.
 * Recebe um objeto parcial com as colunas da tabela.
 */
export async function recordAudit(
  supabase: SupabaseClient,
  entry: {
    user_id: string | null;
    action: string;
    entity?: string | null;
    entity_id?: string | null;
    ip_address?: string | null;
    user_agent?: string | null;
  }
) {
  const { error } = await supabase.from("audit_log").insert({
    user_id: entry.user_id,
    action: entry.action,
    entity: entry.entity ?? null,
    entity_id: entry.entity_id ?? null,
    ip_address: entry.ip_address ?? null,
    user_agent: entry.user_agent ?? null,
    created_at: new Date().toISOString(),
  });
  if (error) {
    console.error("Audit insert error:", error);
    // Não interrompe a função original; apenas registra no log do runtime
  }
}
