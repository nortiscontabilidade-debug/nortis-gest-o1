-- Supabase migration: fase 1 – usuários, autenticação e auditoria
-- ------------------------------------------------------------
-- 1. Perfil de usuário (extensão da tabela auth.users)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
    id uuid PRIMARY KEY REFERENCES auth.users ON DELETE CASCADE,
    full_name text NOT NULL,
    role text NOT NULL CHECK (role IN ('admin', 'collaborator')),
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now()
);

-- Atualiza timestamp on update
CREATE FUNCTION public.update_timestamp()
RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_profiles_timestamp
BEFORE UPDATE ON public.profiles
FOR EACH ROW EXECUTE FUNCTION public.update_timestamp();

-- ------------------------------------------------------------
-- 2. Auditoria de login
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.login_audit (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id uuid REFERENCES auth.users ON DELETE SET NULL,
    ip_address inet,
    user_agent text,
    success boolean NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------
-- 3. Auditoria genérica de ações sensíveis (ex.: revelar credencial)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_log (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id uuid REFERENCES auth.users ON DELETE SET NULL,
    action text NOT NULL, -- e.g., 'reveal', 'copy', 'create', 'update', 'delete'
    entity text,          -- exemplo: 'company', 'credential'
    entity_id uuid,
    ip_address inet,
    user_agent text,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------
-- 4. Função para revogação imediata de sessões de um usuário
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.revoke_user_sessions(p_user_id uuid)
RETURNS void AS $$
BEGIN
    PERFORM auth.revoke_refresh_token(p_user_id);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ------------------------------------------------------------
-- 5. Row Level Security (RLS) – perfis
-- ------------------------------------------------------------
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- Usuário pode ler/editar seu próprio perfil
CREATE POLICY "self read" ON public.profiles
    FOR SELECT USING (auth.uid() = id);
CREATE POLICY "self update" ON public.profiles
    FOR UPDATE USING (auth.uid() = id);

-- Administradores podem ler/editar todos os perfis
CREATE POLICY "admin read" ON public.profiles
    FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));
CREATE POLICY "admin update" ON public.profiles
    FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));

-- ------------------------------------------------------------
-- 6. RLS – auditoria de login (apenas inserção via função segura)
-- ------------------------------------------------------------
ALTER TABLE public.login_audit ENABLE ROW LEVEL SECURITY;
CREATE POLICY "allow insert" ON public.login_audit
    FOR INSERT WITH CHECK (true);

-- ------------------------------------------------------------
-- 7. RLS – audit_log (apenas inserção via funções de back‑end)
-- ------------------------------------------------------------
ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY "allow insert" ON public.audit_log
    FOR INSERT WITH CHECK (true);

-- ------------------------------------------------------------
-- Extensões necessárias
-- ------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Comentários para documentação
COMMENT ON TABLE public.profiles IS 'Perfil de usuário complementar ao auth.users';
COMMENT ON COLUMN public.profiles.role IS 'admin = controle total; collaborator = permissões individuais definidas nas funções posteriores';
COMMENT ON FUNCTION public.revoke_user_sessions(uuid) IS 'Revoga todos os refresh tokens do usuário, forçando logout imediato';
