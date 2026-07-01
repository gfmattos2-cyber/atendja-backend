-- Atendja SaaS - PostgreSQL Database Schema
-- Habilitar suporte a UUIDs nativos se não estiver ativo
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ==========================================
-- 1. TABELA DE TENANTS (CLIENTES DO SAAS)
-- ==========================================
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    status_assinatura VARCHAR(50) NOT NULL DEFAULT 'trial', -- active, trial, canceled, suspended
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Indexar buscas ativas por e-mail (login) e soft delete
CREATE INDEX IF NOT EXISTS idx_tenants_active ON tenants(email) WHERE deleted_at IS NULL;

-- ==========================================
-- 2. TABELA DE INSTÂNCIAS WHATSAPP (EVOLUTION API)
-- ==========================================
CREATE TABLE IF NOT EXISTS whatsapp_instances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    instance_name VARCHAR(100) UNIQUE NOT NULL, -- O nome/slug da instância na Evolution
    status_conexao VARCHAR(50) NOT NULL DEFAULT 'DISCONNECTED', -- CONNECTED, DISCONNECTED, CONNECTING
    qrcode_base64 TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_whatsapp_instances_tenant ON whatsapp_instances(tenant_id);

-- ==========================================
-- 3. TABELA DE CONFIGURAÇÕES DOS AGENTES DE IA
-- ==========================================
CREATE TABLE IF NOT EXISTS agent_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID UNIQUE NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    prompt_sistema TEXT NOT NULL,
    nicho VARCHAR(100) NOT NULL, -- gym, laundry, dental, etc.
    limite_mensal INTEGER NOT NULL DEFAULT 1000,
    consumo_atual INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- 4. TABELA DE LOGS DE USO (HISTÓRICO E COTAS)
-- ==========================================
CREATE TABLE IF NOT EXISTS usage_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    whatsapp_instance_id UUID REFERENCES whatsapp_instances(id) ON DELETE SET NULL,
    type VARCHAR(50) NOT NULL, -- message_sent, message_received, token_count
    tokens_used INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Índices compostos de performance para cota mensal e relatórios
CREATE INDEX IF NOT EXISTS idx_usage_logs_tenant_date ON usage_logs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_logs_instance ON usage_logs (whatsapp_instance_id);

---------------------------------------------------------
-- ATIVAÇÃO DE ROW LEVEL SECURITY (RLS) PARA TENANT ISOLATION
---------------------------------------------------------
ALTER TABLE whatsapp_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_logs ENABLE ROW LEVEL SECURITY;

-- Políticas baseadas na variável de sessão 'app.current_tenant_id'
DROP POLICY IF EXISTS whatsapp_instances_isolation ON whatsapp_instances;
CREATE POLICY whatsapp_instances_isolation ON whatsapp_instances
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS agent_configs_isolation ON agent_configs;
CREATE POLICY agent_configs_isolation ON agent_configs
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS usage_logs_isolation ON usage_logs;
CREATE POLICY usage_logs_isolation ON usage_logs
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
