-- Supabase migration: fase 2 – empresas, sócios, certificados, acessos, cofre e permissões de colaborador
-- -----------------------------------------------------------------------------
-- 1. Tabela de empresas
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.companies (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    name text NOT NULL,
    cnpj text,
    address text,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now()
);

-- 2. Tabela de sócios (partners)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.partners (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id uuid REFERENCES public.companies(id) ON DELETE CASCADE,
    full_name text NOT NULL,
    cpf text,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now()
);

-- 3. Tabela de certificados
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificates (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id uuid REFERENCES public.companies(id) ON DELETE CASCADE,
    type text NOT NULL,
    expires_at date,
    storage_path text NOT NULL, -- caminho no Supabase Storage
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now()
);

-- 4. Tabela de acessos (sem senha nesta fase)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.accesses (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id uuid REFERENCES public.companies(id) ON DELETE CASCADE,
    service_name text NOT NULL,
    description text,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now()
);

-- 5. Cofre de credenciais (secrets) – valores criptografados
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.secrets (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id uuid REFERENCES public.companies(id) ON DELETE CASCADE,
    key_name text NOT NULL,
    encrypted_value bytea NOT NULL,
    iv bytea NOT NULL,
    tag bytea NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now()
);

-- 6. Relacionamento de colaboradores com empresas (permissões individuais)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.company_collaborators (
    user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
    company_id uuid REFERENCES public.companies(id) ON DELETE CASCADE,
    -- Permissões granulares podem ser armazenadas como JSON, ex: {"view":true,"edit":true,...}
    permissions jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (user_id, company_id)
);

-- -----------------------------------------------------------------------------
-- Triggers de timestamp (reuso da função já criada)
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_companies_timestamp BEFORE UPDATE ON public.companies FOR EACH ROW EXECUTE FUNCTION public.update_timestamp();
CREATE TRIGGER trg_partners_timestamp BEFORE UPDATE ON public.partners FOR EACH ROW EXECUTE FUNCTION public.update_timestamp();
CREATE TRIGGER trg_certificates_timestamp BEFORE UPDATE ON public.certificates FOR EACH ROW EXECUTE FUNCTION public.update_timestamp();
CREATE TRIGGER trg_accesses_timestamp BEFORE UPDATE ON public.accesses FOR EACH ROW EXECUTE FUNCTION public.update_timestamp();
CREATE TRIGGER trg_secrets_timestamp BEFORE UPDATE ON public.secrets FOR EACH ROW EXECUTE FUNCTION public.update_timestamp();

-- -----------------------------------------------------------------------------
-- Row Level Security (RLS)
-- -----------------------------------------------------------------------------

-- Empresas
ALTER TABLE public.companies ENABLE ROW LEVEL SECURITY;
-- Admins podem tudo
CREATE POLICY "admin all" ON public.companies FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin')) WITH CHECK (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));
-- Colaboradores só nas empresas às quais foram vinculados
CREATE POLICY "collaborator access" ON public.companies FOR SELECT USING (EXISTS (SELECT 1 FROM public.company_collaborators cc WHERE cc.user_id = auth.uid() AND cc.company_id = id));
CREATE POLICY "collaborator modify" ON public.companies FOR INSERT, UPDATE, DELETE USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin')) WITH CHECK (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));

-- Partners
ALTER TABLE public.partners ENABLE ROW LEVEL SECURITY;
CREATE POLICY "partner admin" ON public.partners FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin')) WITH CHECK (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));
CREATE POLICY "partner collaborator" ON public.partners FOR SELECT USING (EXISTS (SELECT 1 FROM public.company_collaborators cc WHERE cc.user_id = auth.uid() AND cc.company_id = company_id));

-- Certificates
ALTER TABLE public.certificates ENABLE ROW LEVEL SECURITY;
CREATE POLICY "cert admin" ON public.certificates FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin')) WITH CHECK (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));
CREATE POLICY "cert collaborator" ON public.certificates FOR SELECT USING (EXISTS (SELECT 1 FROM public.company_collaborators cc WHERE cc.user_id = auth.uid() AND cc.company_id = company_id));

-- Accesses (sem segredo)
ALTER TABLE public.accesses ENABLE ROW LEVEL SECURITY;
CREATE POLICY "access admin" ON public.accesses FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin')) WITH CHECK (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));
CREATE POLICY "access collaborator" ON public.accesses FOR SELECT USING (EXISTS (SELECT 1 FROM public.company_collaborators cc WHERE cc.user_id = auth.uid() AND cc.company_id = company_id));

-- Secrets – cofre
ALTER TABLE public.secrets ENABLE ROW LEVEL SECURITY;
-- Apenas admins podem inserir/alterar; colaboradores podem somente SELECT (revelar) via funções privilegiadas
CREATE POLICY "secret admin modify" ON public.secrets FOR INSERT, UPDATE, DELETE USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin')) WITH CHECK (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));
CREATE POLICY "secret collaborator read" ON public.secrets FOR SELECT USING (EXISTS (SELECT 1 FROM public.company_collaborators cc WHERE cc.user_id = auth.uid() AND cc.company_id = company_id));

-- Company Collaborators table – apenas admins gerenciam
ALTER TABLE public.company_collaborators ENABLE ROW LEVEL SECURITY;
CREATE POLICY "collab admin" ON public.company_collaborators FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin')) WITH CHECK (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));

-- -----------------------------------------------------------------------------
-- Comentários
-- -----------------------------------------------------------------------------
COMMENT ON TABLE public.companies IS 'Empresas cadastradas no sistema.';
COMMENT ON TABLE public.partners IS 'Sócios / representantes das empresas.';
COMMENT ON TABLE public.certificates IS 'Certificados armazenados (arquivo no Storage).';
COMMENT ON TABLE public.accesses IS 'Registros de acessos (sem senhas nesta fase).';
COMMENT ON TABLE public.secrets IS 'Cofre de credenciais criptografadas (AES‑256‑GCM).';
COMMENT ON TABLE public.company_collaborators IS 'Relacionamento entre usuários colaborador e empresas, com permissões granulares.';
