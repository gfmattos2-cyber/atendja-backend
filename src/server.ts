import express, { Request, Response, NextFunction } from 'express';
import { Pool } from 'pg';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import dns from 'dns';

// Forçar Node.js a priorizar conexões IPv4 sobre IPv6.
// Isso resolve o erro ENETUNREACH em ambientes (como Railway) sem roteamento IPv6 ativo.
dns.setDefaultResultOrder('ipv4first');

// Carregar variáveis de ambiente
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || 'atendja_fallback_secret_key_2026';

// Configurar pool de conexões com o PostgreSQL
// SSL sempre ativo — banco hospedado no Supabase exige SSL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Rota de Health Check para diagnóstico de banco de dados e deploy
app.get('/health', async (req: Request, res: Response) => {
  try {
    const start = Date.now();
    const dbTest = await pool.query('SELECT NOW()');
    return res.status(200).json({
      status: 'healthy',
      database: 'connected',
      timestamp: dbTest.rows[0].now,
      latencyMs: Date.now() - start
    });
  } catch (err: any) {
    return res.status(500).json({
      status: 'unhealthy',
      database: 'error',
      message: err.message
    });
  }
});

// Middleware para parsear JSON
app.use(express.json());

// Habilitar CORS para permitir que o frontend (Vercel ou local) se conecte à API
app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Servir os arquivos estáticos do dashboard na rota /dashboard
app.use('/dashboard', express.static(path.join(__dirname, '../../atendja-dashboard')));

// Log de requisições simples
app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ==========================================
// MIDDLEWARES DE SEGURANÇA
// ==========================================

// 1. Middleware de Autenticação JWT (para clientes no Dashboard)
const authenticateJWT = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expects: Bearer <token>

  if (!token) {
    return res.status(401).json({ error: 'Acesso negado. Token de sessão ausente ou inválido.' });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret) as { tenantId: string; email: string };
    (req as any).user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Sessão expirada ou inválida. Faça login novamente.' });
  }
};

// 2. Middleware de Autenticação Interna (n8n -> Backend)
const authenticateInternalToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  const expectedToken = process.env.N8N_INTERNAL_TOKEN;

  if (!expectedToken) {
    console.error('ERRO: N8N_INTERNAL_TOKEN não configurado no arquivo .env!');
    return res.status(500).json({ error: 'Erro de configuração do servidor interno' });
  }

  if (!token || token !== expectedToken) {
    return res.status(401).json({ error: 'Acesso não autorizado. Token interno inválido ou ausente.' });
  }

  next();
};

// Helper para chamadas seguras à Evolution API
const callEvolutionAPI = async (endpoint: string, method: string = 'GET', body: any = null) => {
  const url = `${process.env.EVOLUTION_API_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    'apikey': process.env.EVOLUTION_API_GLOBAL_TOKEN || ''
  };

  const options: RequestInit = {
    method,
    headers,
    body: body ? JSON.stringify(body) : null
  };

  try {
    const response = await fetch(url, options);
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Evolution API HTTP error ${response.status}: ${errorText}`);
    }
    return await response.json();
  } catch (err: any) {
    console.error(`Erro ao chamar a Evolution API (${url}):`, err.message);
    throw err;
  }
};

// Helper para configurar webhook e parâmetros de ignoreGroups na Evolution API
async function configureInstance(instanceName: string): Promise<void> {
  const n8nWebhookUrl = process.env.N8N_WEBHOOK_URL;
  if (!n8nWebhookUrl) {
    console.warn('[Evolution Configure] N8N_WEBHOOK_URL não está configurada no .env. Ignorando configuração de webhook.');
    return;
  }

  try {
    console.log(`[Evolution Configure] Iniciando configuração para a instância: ${instanceName}`);

    // 1. Configurar Webhook (com chave 'webhook' aninhada exigida pelo Evolution)
    await callEvolutionAPI(`/webhook/set/${instanceName}`, 'POST', {
      webhook: {
        enabled: true,
        url: n8nWebhookUrl,
        webhookByEvents: false,
        events: [
          'MESSAGES_UPSERT'
        ]
      }
    });
    console.log(`[Evolution Configure] Webhook configurado com sucesso para ${instanceName}. URL: ${n8nWebhookUrl}`);

    // 2. Configurar Definições da Instância (com syncFullHistory exigido pelo Evolution)
    await callEvolutionAPI(`/settings/set/${instanceName}`, 'POST', {
      rejectCall: false,
      groupsIgnore: true,
      alwaysOnline: true,
      readMessages: true,
      readStatus: false,
      syncFullHistory: false
    });
    console.log(`[Evolution Configure] Definições (groupsIgnore, syncFullHistory, etc.) configuradas com sucesso para ${instanceName}.`);

  } catch (err: any) {
    console.error(`[Evolution Configure] Falha ao configurar a instância ${instanceName}:`, err.message);
  }
}

// ==========================================
// ROTAS PÚBLICAS / SAÚDE
// ==========================================
app.get('/api/health', (req: Request, res: Response) => {
  res.status(200).json({
    status: 'online',
    timestamp: new Date().toISOString()
  });
});

// ==========================================
// ROTAS DE AUTENTICAÇÃO (CADASTRO E LOGIN)
// ==========================================

/**
 * POST /api/auth/register
 * Cadastro de novo cliente/tenant com criação de configs padrões
 */
app.post('/api/auth/register', async (req: Request, res: Response) => {
  const { name, email, password, nicho } = req.body;

  if (!name || !email || !password || !nicho) {
    return res.status(400).json({ error: 'Todos os campos (name, email, password, nicho) são obrigatórios.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verificar se e-mail já existe
    const checkEmail = await client.query('SELECT id FROM tenants WHERE email = $1', [email]);
    if (checkEmail.rows.length > 0) {
      client.release();
      return res.status(400).json({ error: 'Este endereço de e-mail já está cadastrado.' });
    }

    // Hash da senha
    const passwordHash = await bcrypt.hash(password, 10);

    // 1. Inserir Tenant
    const insertTenant = `
      INSERT INTO tenants (name, email, password_hash, status_assinatura)
      VALUES ($1, $2, $3, 'trial')
      RETURNING id, name, email, status_assinatura;
    `;
    const tenantRes = await client.query(insertTenant, [name, email, passwordHash]);
    const tenant = tenantRes.rows[0];

    // Prompts padrão por nicho
    let promptPadrao = 'Você é um assistente virtual prestativo.';
    if (nicho === 'gym') {
      promptPadrao = `Você é o assistente virtual da academia ${name}. Responda dúvidas sobre mensalidades, planos (Mensal: R$ 150, Trimestral: R$ 380) e horários de treino de CrossFit. Seja amigável e incentive a agendar uma aula experimental.`;
    } else if (nicho === 'laundry') {
      promptPadrao = `Você é o assistente virtual da lavanderia self-service ${name}. Explique que o funcionamento é por ciclos (Lavagem: R$ 15, Secagem: R$ 15), indique as formas de pagamento disponíveis e dê instruções de uso seguro das máquinas.`;
    }

    // 2. Criar Agent Config padrão
    const insertConfig = `
      INSERT INTO agent_configs (tenant_id, prompt_sistema, nicho, limite_mensal, consumo_atual)
      VALUES ($1, $2, $3, 1000, 0);
    `;
    await client.query(insertConfig, [tenant.id, promptPadrao, nicho]);

    // 3. Criar instância de WhatsApp padrão associada
    const instanceSlug = `instancia_${tenant.id.split('-')[0]}`;
    const insertInstance = `
      INSERT INTO whatsapp_instances (tenant_id, instance_name, status_conexao)
      VALUES ($1, $2, 'DISCONNECTED');
    `;
    await client.query(insertInstance, [tenant.id, instanceSlug]);

    // Tentar criar a instância programaticamente na Evolution API
    try {
      await callEvolutionAPI('/instance/create', 'POST', {
        instanceName: instanceSlug,
        token: `token_${tenant.id.split('-')[0]}`,
        qrcode: true,
        integration: 'WHATSAPP-BAILEYS'
      });
      console.log(`Instância '${instanceSlug}' criada com sucesso na Evolution API.`);
      
      // Configurar webhook e ignoreGroups automaticamente
      await configureInstance(instanceSlug);
    } catch (evoErr: any) {
      // Falha na Evolution API não deve dar rollback na criação da conta do usuário.
      // O usuário pode tentar inicializar/recriar depois no painel de conexão.
      console.warn(`Aviso: Não foi possível criar a instância na Evolution API durante o cadastro:`, evoErr.message);
    }

    await client.query('COMMIT');

    // Gerar token de sessão JWT
    const token = jwt.sign({ tenantId: tenant.id, email: tenant.email }, jwtSecret, { expiresIn: '7d' });

    return res.status(201).json({
      message: 'Conta criada com sucesso!',
      token,
      user: {
        id: tenant.id,
        name: tenant.name,
        email: tenant.email,
        status_assinatura: tenant.status_assinatura,
        nicho,
        instanceName: instanceSlug
      }
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erro no cadastro do usuário:', error);
    return res.status(500).json({ error: 'Erro interno durante o processamento do cadastro.' });
  } finally {
    client.release();
  }
});

/**
 * POST /api/auth/login
 * Login do cliente com geração de JWT
 */
app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
  }

  try {
    const query = `
      SELECT t.id, t.name, t.email, t.password_hash, t.status_assinatura, a.nicho, w.instance_name
      FROM tenants t
      LEFT JOIN agent_configs a ON t.id = a.tenant_id
      LEFT JOIN whatsapp_instances w ON t.id = w.tenant_id
      WHERE t.email = $1 AND t.deleted_at IS NULL;
    `;
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'E-mail ou senha incorretos.' });
    }

    const user = result.rows[0];

    // Validar senha
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: 'E-mail ou senha incorretos.' });
    }

    // Gerar token de sessão
    const token = jwt.sign({ tenantId: user.id, email: user.email }, jwtSecret, { expiresIn: '7d' });

    return res.status(200).json({
      message: 'Login realizado com sucesso!',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        status_assinatura: user.status_assinatura,
        nicho: user.nicho,
        instanceName: user.instance_name
      }
    });

  } catch (error) {
    console.error('Erro ao realizar login:', error);
    return res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// ==========================================
// ROTAS CLIENTE (PROXY DA EVOLUTION API)
// ==========================================

/**
 * GET /api/tenant/config
 * Retorna as configurações do robô, cota e status do onboarding do inquilino logado
 */
app.get('/api/tenant/config', authenticateJWT, async (req: Request, res: Response) => {
  const tenantId = (req as any).user.tenantId;

  try {
    const query = `
      SELECT t.name, a.prompt_sistema, a.nicho, a.limite_mensal, a.consumo_atual, a.onboarding_completed, a.onboarding_data
      FROM tenants t
      JOIN agent_configs a ON t.id = a.tenant_id
      WHERE t.id = $1 AND t.deleted_at IS NULL;
    `;
    const result = await pool.query(query, [tenantId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Configurações do inquilino não encontradas.' });
    }

    return res.status(200).json(result.rows[0]);
  } catch (error: any) {
    console.error('Erro ao buscar configurações do inquilino:', error.message);
    return res.status(500).json({ error: 'Falha ao buscar configurações.' });
  }
});

// Helper para gerar prompt com base no nicho e respostas do onboarding
function generateSystemPrompt(nicho: string, data: any): string {
  const { name, agent_name, agent_gender, address, support_phone, hours, holidays, operation_type, tone, rules, faq } = data;
  
  const genderTerm = {
    female: 'como a assistente virtual (gênero feminino)',
    male: 'como o assistente virtual (gênero masculino)',
    neutral: 'como o atendente virtual (gênero neutro)'
  }[agent_gender as 'female' | 'male' | 'neutral'] || 'como assistente virtual';

  const toneInstruction = {
    friendly: 'Use um tom amigável, acolhedor e entusiasta. Use emojis de forma moderada.',
    formal: 'Use um tom profissional, polido e formal. Evite gírias ou termos excessivamente informais.',
    direct: 'Use um tom objetivo, direto e prático. Responda de forma clara e sem rodeios.'
  }[tone as 'friendly' | 'formal' | 'direct'] || 'Use um tom prestativo e educado.';

  const holidayRule = {
    yes: 'Funcionamos normalmente nos feriados.',
    reduced: 'Funcionamos com horário reduzido nos feriados.',
    no: 'Não funcionamos nos feriados.',
    depends: 'O funcionamento em feriados depende de aviso prévio.'
  }[holidays as 'yes' | 'reduced' | 'no' | 'depends'] || '';

  const operationRule = operation_type === 'automated' 
    ? 'Nossa operação é 100% automatizada/self-service, ou seja, não há atendentes presenciais no local.' 
    : 'Temos atendentes presenciais no local para auxiliar no que for necessário.';

  const supportRule = support_phone ? `Se houver dúvidas complexas ou o cliente solicitar atendimento humano, peça para ele entrar em contato com o suporte pelo telefone/WhatsApp: ${support_phone}.` : '';

  const additionalRules = rules ? `Regras extras importantes: ${rules}.` : '';
  const faqRule = faq ? `Perguntas Frequentes (FAQ) para usar como guia de respostas:\n${faq}` : '';

  let basePrompt = `Seu nome é "${agent_name}". Você atua ${genderTerm} do estabelecimento "${name}".
Endereço completo: ${address}.
Horário de funcionamento: ${hours}.
Funcionamento em Feriados: ${holidayRule}
Tipo de Operação: ${operationRule}
${supportRule}
${additionalRules}
${faqRule}
Instruções de comportamento:
1. ${toneInstruction}
2. Nunca invente dados sobre preços, horários ou regras. Se não souber a informação, utilize o contato de suporte humano.`;

  if (nicho === 'laundry') {
    return `${basePrompt}
Nossos preços por ciclo de máquina são: Ciclo de Lavagem: R$ ${data.wash_price}, Ciclo de Secagem: R$ ${data.dry_price}.
Aceitamos as seguintes formas de pagamento: ${data.payments}.
Instruções de uso: Cada ciclo dura cerca de 35 minutos. O sabão e o amaciante são dosados automaticamente pelas máquinas (já inclusos no valor) ou devem ser trazidos pelo cliente (conforme a regra local).`;
  } else if (nicho === 'gym') {
    return `${basePrompt}
Nossos planos de mensalidade ativos são: Plano Mensal: R$ ${data.monthly_price}, Plano Trimestral: R$ ${data.quarterly_price}.
${data.loyalty_plans ? `Planos corporativos/programas de fidelidade: ${data.loyalty_plans}.` : ''}
Sobre agendamento de aulas experimentais: ${data.trial_policy}.
Incentive sempre o usuário a agendar uma aula experimental caso ele seja um visitante de primeira viagem.`;
  }
  
  return basePrompt;
}

/**
 * POST /api/tenant/onboarding
 * Recebe as respostas estruturadas do formulário, gera o prompt de IA e conclui o onboarding
 */
app.post('/api/tenant/onboarding', authenticateJWT, async (req: Request, res: Response) => {
  const tenantId = (req as any).user.tenantId;
  const onboardingData = req.body;
  const { nicho, name } = onboardingData;

  if (!nicho || !name) {
    return res.status(400).json({ error: 'Os campos nicho e name são obrigatórios.' });
  }

  try {
    // 1. Atualizar o nome da empresa na tabela 'tenants'
    await pool.query('UPDATE tenants SET name = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', [name, tenantId]);

    // 2. Gerar o prompt de sistema personalizado a partir dos dados do formulário
    const generatedPrompt = generateSystemPrompt(nicho, onboardingData);

    // 3. Salvar o prompt, o nicho, o JSON de dados e marcar o onboarding como completo
    const updateConfigQuery = `
      UPDATE agent_configs
      SET prompt_sistema = $1, 
          nicho = $2, 
          onboarding_completed = true, 
          onboarding_data = $3, 
          updated_at = CURRENT_TIMESTAMP
      WHERE tenant_id = $4
      RETURNING prompt_sistema, nicho, onboarding_completed, onboarding_data;
    `;
    const result = await pool.query(updateConfigQuery, [
      generatedPrompt,
      nicho,
      JSON.stringify(onboardingData),
      tenantId
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Configuração do agente não encontrada.' });
    }

    return res.status(200).json({
      success: true,
      message: 'Onboarding concluído com sucesso e prompt de IA gerado.',
      config: result.rows[0]
    });

  } catch (error: any) {
    console.error('Erro ao salvar onboarding do inquilino:', error.message);
    return res.status(500).json({ error: 'Falha ao processar dados de onboarding.' });
  }
});

/**
 * GET /api/whatsapp/status
 * Verifica o status de conexão da instância do usuário logado
 */
app.get('/api/whatsapp/status', authenticateJWT, async (req: Request, res: Response) => {
  const tenantId = (req as any).user.tenantId;

  try {
    // Buscar nome da instância associada no DB
    const instQuery = await pool.query('SELECT instance_name, status_conexao FROM whatsapp_instances WHERE tenant_id = $1', [tenantId]);
    if (instQuery.rows.length === 0) {
      return res.status(404).json({ error: 'Instância de WhatsApp não configurada para esta conta.' });
    }

    const { instance_name } = instQuery.rows[0];

    // Consultar status na Evolution API
    let connected = false;
    let state = 'disconnected';

    try {
      const evoStatus = await callEvolutionAPI(`/instance/connectionState/${instance_name}`);
      state = evoStatus.instance?.state || 'disconnected';
      connected = state === 'open';

      // Sincronizar status no banco de dados local
      await pool.query(
        'UPDATE whatsapp_instances SET status_conexao = $1 WHERE tenant_id = $2',
        [connected ? 'CONNECTED' : 'DISCONNECTED', tenantId]
      );
    } catch (evoErr: any) {
      // Se a instância não existir na Evolution API, vamos recriá-la
      if (evoErr.message.includes('404')) {
        console.log(`Instância '${instance_name}' não existe na Evolution. Recriando...`);
        await callEvolutionAPI('/instance/create', 'POST', {
          instanceName: instance_name,
          token: `token_${tenantId.split('-')[0]}`,
          qrcode: true,
          integration: 'WHATSAPP-BAILEYS'
        });
        
        // Configurar webhook e ignoreGroups automaticamente
        await configureInstance(instance_name);
      }
    }

    return res.status(200).json({
      connected,
      state,
      instanceName: instance_name
    });

  } catch (error: any) {
    console.error('Erro na rota whatsapp/status:', error.message);
    return res.status(500).json({ error: 'Falha ao buscar status do WhatsApp.' });
  }
});

/**
 * GET /api/whatsapp/qrcode
 * Solicita e retorna o QR Code da Evolution API em base64
 */
app.get('/api/whatsapp/qrcode', authenticateJWT, async (req: Request, res: Response) => {
  const tenantId = (req as any).user.tenantId;

  try {
    const instQuery = await pool.query('SELECT instance_name FROM whatsapp_instances WHERE tenant_id = $1', [tenantId]);
    if (instQuery.rows.length === 0) {
      return res.status(404).json({ error: 'Instância de WhatsApp não cadastrada.' });
    }

    const { instance_name } = instQuery.rows[0];

    // Chama o connect da Evolution para forçar a geração do QR code
    const evoConnect = await callEvolutionAPI(`/instance/connect/${instance_name}`);
    console.log('[DEBUG Evolution API] Connect Response:', JSON.stringify(evoConnect, null, 2));

    // Formato 1: qrcode.base64 no objeto aninhado
    if (evoConnect && evoConnect.qrcode) {
      return res.status(200).json({
        qrcode: evoConnect.qrcode.base64,
        pairingCode: evoConnect.pairingCode || null
      });
    }

    // Formato 2: base64 diretamente na raiz do objeto (Nova versão da Evolution API)
    if (evoConnect && evoConnect.base64) {
      return res.status(200).json({
        qrcode: evoConnect.base64,
        pairingCode: evoConnect.pairingCode || null
      });
    }

    // Caso o dispositivo já esteja conectado
    if (evoConnect && (evoConnect.state === 'open' || evoConnect.instance?.state === 'open')) {
      return res.status(200).json({ connected: true, message: 'O WhatsApp já está ativo.' });
    }

    return res.status(500).json({ error: 'Evolution API não retornou o QR Code.' });

  } catch (error: any) {
    console.error('Erro na rota whatsapp/qrcode:', error.message);
    return res.status(500).json({ error: 'Falha ao gerar o QR Code de pareamento.' });
  }
});

/**
 * POST /api/whatsapp/logout
 * Desconecta a conta de WhatsApp (Logout)
 */
app.post('/api/whatsapp/logout', authenticateJWT, async (req: Request, res: Response) => {
  const tenantId = (req as any).user.tenantId;

  try {
    const instQuery = await pool.query('SELECT instance_name FROM whatsapp_instances WHERE tenant_id = $1', [tenantId]);
    if (instQuery.rows.length === 0) {
      return res.status(404).json({ error: 'Instância de WhatsApp não cadastrada.' });
    }

    const { instance_name } = instQuery.rows[0];

    // Enviar logout para a Evolution API
    await callEvolutionAPI(`/instance/logout/${instance_name}`, 'POST');

    // Atualizar no banco de dados local
    await pool.query('UPDATE whatsapp_instances SET status_conexao = $1 WHERE tenant_id = $2', ['DISCONNECTED', tenantId]);

    return res.status(200).json({ success: true, message: 'WhatsApp desconectado com sucesso.' });

  } catch (error: any) {
    console.error('Erro na rota whatsapp/logout:', error.message);
    return res.status(500).json({ error: 'Falha ao desconectar o dispositivo.' });
  }
});

// ==========================================
// WEBHOOK PÚBLICO DA EVOLUTION API (DESCONEXÕES FÍSICAS)
// ==========================================

/**
 * POST /api/whatsapp/events
 * Recebe eventos de status de conexão disparados diretamente pela Evolution API
 */
app.post('/api/whatsapp/events', async (req: Request, res: Response) => {
  const { event, data } = req.body;

  try {
    if (event === 'connection.update') {
      const instanceName = data.instance; // Ex: 'instancia_a34bc12'
      const state = data.state; // 'open', 'close', etc.

      console.log(`[Evolution Webhook] Evento: connection.update | Instância: ${instanceName} | Estado: ${state}`);

      const statusMap = state === 'open' ? 'CONNECTED' : 'DISCONNECTED';

      // Se a conexão foi estabelecida (QR code escaneado), configura webhook/ignoreGroups automaticamente
      if (state === 'open') {
        await configureInstance(instanceName);
      }

      // Atualiza o status no nosso banco de dados baseado no nome da instância
      const updateRes = await pool.query(
        'UPDATE whatsapp_instances SET status_conexao = $1 WHERE instance_name = $2 RETURNING tenant_id',
        [statusMap, instanceName]
      );

      if ((updateRes.rowCount ?? 0) > 0) {
        console.log(`[Evolution Webhook] Status da instância '${instanceName}' atualizado para '${statusMap}'.`);
      }
    }
  } catch (err: any) {
    console.error('Erro ao processar webhook da Evolution API:', err.message);
  }

  // Sempre retornar 200 OK para a Evolution API não ficar tentando enviar novamente
  return res.status(200).send('OK');
});

// ==========================================
// ROTAS INTERNAS PROTEGIDAS (PARA O n8n)
// ==========================================

/**
 * GET /api/internal/instance-config
 * Busca o prompt e configurações do cliente baseado no nome da instância
 */
app.get('/api/internal/instance-config', authenticateInternalToken, async (req: Request, res: Response) => {
  const instanceName = req.query.instanceName as string;
  const telefone = req.query.telefone as string;

  if (!instanceName) {
    return res.status(400).json({ error: 'Parâmetro instanceName é obrigatório.' });
  }

  try {
    const query = `
      SELECT 
        t.id AS tenant_id,
        t.name AS nome_empresa,
        t.status_assinatura,
        t.plano,
        w.id AS whatsapp_instance_id,
        w.instance_name,
        a.prompt_sistema,
        a.nicho,
        a.limite_mensal,
        a.consumo_atual,
        a.onboarding_data
      FROM tenants t
      JOIN whatsapp_instances w ON t.id = w.tenant_id
      JOIN agent_configs a ON t.id = a.tenant_id
      WHERE w.instance_name = $1 
        AND t.deleted_at IS NULL 
        AND w.deleted_at IS NULL;
    `;

    const result = await pool.query(query, [instanceName]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: `Configurações não encontradas para a instância '${instanceName}'.` });
    }

    const config = result.rows[0];

    const statusPermitidos = ['active', 'trialing', 'trial'];
    if (!statusPermitidos.includes(config.status_assinatura)) {
      return res.status(403).json({
        error: 'Assinatura inativa ou suspensa.',
        status_assinatura: config.status_assinatura
      });
    }

    if (config.consumo_atual >= config.limite_mensal) {
      return res.status(403).json({
        error: 'Cota mensal de mensagens excedida.',
        consumo_atual: config.consumo_atual,
        limite_mensal: config.limite_mensal
      });
    }

    // Verificar se o agente está pausado para este cliente específico
    let paused = false;
    if (telefone) {
      const queryPausa = `
        SELECT 1 FROM agent_customer_pauses
        WHERE instance_name = $1 AND telefone = $2 AND paused_until > NOW();
      `;
      const resPausa = await pool.query(queryPausa, [instanceName, telefone]);
      paused = resPausa.rows.length > 0;
    }

    let support_phone = '';
    if (config.onboarding_data) {
      const data = typeof config.onboarding_data === 'string' ? JSON.parse(config.onboarding_data) : config.onboarding_data;
      support_phone = data.telefoneEscalonamento || data.telefoneSuporte || data.telefone || '';
      // Limpar formatação para n8n
      support_phone = support_phone.replace(/\D/g, '');
    }

    return res.status(200).json({
      ...config,
      paused,
      support_phone
    });

  } catch (error) {
    console.error('Erro ao buscar configuração da instância:', error);
    return res.status(500).json({ error: 'Erro interno no banco de dados.' });
  }
});

/**
 * POST /api/internal/usage/log
 * Registra consumo de tokens/mensagens de forma atômica sob RLS
 */
app.post('/api/internal/usage/log', authenticateInternalToken, async (req: Request, res: Response) => {
  const { tenantId, whatsappInstanceId, type, tokensUsed } = req.body;

  if (!tenantId || !type) {
    return res.status(400).json({ error: 'Os campos tenantId e type são obrigatórios.' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Configurar variável de sessão para Row Level Security
    await client.query("SET LOCAL app.current_tenant_id = $1", [tenantId]);

    const insertLogQuery = `
      INSERT INTO usage_logs (tenant_id, whatsapp_instance_id, type, tokens_used)
      VALUES ($1, $2, $3, $4)
      RETURNING id;
    `;
    await client.query(insertLogQuery, [
      tenantId,
      whatsappInstanceId || null,
      type,
      tokensUsed || 0
    ]);

    const updateConfigQuery = `
      UPDATE agent_configs
      SET consumo_atual = consumo_atual + 1
      WHERE tenant_id = $1 AND consumo_atual < limite_mensal
      RETURNING consumo_atual, limite_mensal;
    `;
    const updateResult = await client.query(updateConfigQuery, [tenantId]);

    if ((updateResult.rowCount ?? 0) === 0) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Não foi possível registrar mensagem. Cota mensal excedida.' });
    }

    await client.query('COMMIT');

    const updatedConfig = updateResult.rows[0];
    return res.status(200).json({
      success: true,
      consumo_atual: updatedConfig.consumo_atual,
      limite_mensal: updatedConfig.limite_mensal
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erro na transação de logs de consumo:', error);
    return res.status(500).json({ error: 'Erro interno na transação do banco de dados.' });
  } finally {
    client.release();
  }
});

/**
 * POST /api/internal/pause
 * Pausa ou reativa o agente de IA para um cliente específico de um inquilino
 */
app.post('/api/internal/pause', authenticateInternalToken, async (req: Request, res: Response) => {
  const { instanceName, telefone, paused, minutes } = req.body;

  if (!instanceName || !telefone) {
    return res.status(400).json({ error: 'Os campos instanceName e telefone são obrigatórios.' });
  }

  try {
    if (paused) {
      const min = minutes || 180; // Padrão: 3 horas (180 minutos)
      const pausedUntil = new Date(Date.now() + min * 60 * 1000);

      const upsertQuery = `
        INSERT INTO agent_customer_pauses (instance_name, telefone, paused_until)
        VALUES ($1, $2, $3)
        ON CONFLICT (instance_name, telefone)
        DO UPDATE SET paused_until = EXCLUDED.paused_until;
      `;
      await pool.query(upsertQuery, [instanceName, telefone, pausedUntil]);
      
      console.log(`[Internal Pause] Instância ${instanceName} - Cliente ${telefone} PAUSADO até ${pausedUntil.toISOString()}`);
      
      return res.status(200).json({
        success: true,
        paused: true,
        paused_until: pausedUntil.toISOString()
      });
    } else {
      const deleteQuery = `
        DELETE FROM agent_customer_pauses
        WHERE instance_name = $1 AND telefone = $2;
      `;
      await pool.query(deleteQuery, [instanceName, telefone]);
      
      console.log(`[Internal Pause] Instância ${instanceName} - Cliente ${telefone} REATIVADO.`);
      
      return res.status(200).json({
        success: true,
        paused: false,
        paused_until: null
      });
    }

  } catch (err: any) {
    console.error('Erro na rota internal/pause:', err.message);
    return res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// ==========================================
// ROTAS DE INTEGRAÇÃO MULTI-TENANT (n8n v1)
// ==========================================

/**
 * GET /v1/tenant/settings
 * Puxa as configurações completas de um tenant baseado no nome da instância
 */
app.get('/v1/tenant/settings', authenticateInternalToken, async (req: Request, res: Response) => {
  const instanceName = req.query.instance as string;

  if (!instanceName) {
    return res.status(400).json({ error: 'Parâmetro instance é obrigatório.' });
  }

  try {
    const query = `
      SELECT 
        t.id AS tenant_id,
        t.name AS nome_empresa,
        t.status_assinatura,
        a.prompt_sistema,
        a.nicho,
        a.onboarding_data
      FROM tenants t
      JOIN whatsapp_instances w ON t.id = w.tenant_id
      JOIN agent_configs a ON t.id = a.tenant_id
      WHERE w.instance_name = $1 
        AND t.deleted_at IS NULL 
        AND w.deleted_at IS NULL;
    `;
    const result = await pool.query(query, [instanceName]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: `Configurações não encontradas para a instância '${instanceName}'.` });
    }

    const row = result.rows[0];

    // Extrair parâmetros do onboarding_data
    let urlFotoPlanos = '';
    let urlFotoHorarios = '';
    let limiteHoraInicio = '00:00';
    let limiteHoraFim = '23:59';
    let diasAtendimento = [1, 2, 3, 4, 5, 6, 7];
    let grupoAlerta = '';

    if (row.onboarding_data) {
      const data = typeof row.onboarding_data === 'string' ? JSON.parse(row.onboarding_data) : row.onboarding_data;
      
      urlFotoPlanos = data.urlFotoPlanos || '';
      urlFotoHorarios = data.urlFotoHorarios || '';
      limiteHoraInicio = data.limiteHoraInicio || '00:00';
      limiteHoraFim = data.limiteHoraFim || '23:59';
      
      if (Array.isArray(data.diasAtendimento)) {
        diasAtendimento = data.diasAtendimento;
      }
      
      const rawSupportPhone = data.telefoneEscalonamento || data.telefoneSuporte || data.telefone || '';
      if (rawSupportPhone) {
        grupoAlerta = `${rawSupportPhone.replace(/\D/g, '')}@s.whatsapp.net`;
      }
    }

    return res.status(200).json({
      tenantId: row.tenant_id,
      nomeEmpresa: row.nome_empresa,
      statusAssinatura: row.status_assinatura,
      promptSistema: row.prompt_sistema,
      nicho: row.nicho,
      urlFotoPlanos,
      urlFotoHorarios,
      limiteHoraInicio,
      limiteHoraFim,
      diasAtendimento,
      grupoAlerta
    });

  } catch (error: any) {
    console.error('Erro ao buscar settings do tenant:', error);
    return res.status(500).json({ error: 'Erro interno no banco de dados.', detail: error.message });
  }
});

/**
 * GET /v1/tenant/pause-status
 * Verifica se um cliente específico está pausado na conversa atual
 */
app.get('/v1/tenant/pause-status', authenticateInternalToken, async (req: Request, res: Response) => {
  const instanceName = req.query.instance as string;
  const telefone = req.query.telefone as string;

  if (!instanceName || !telefone) {
    return res.status(400).json({ error: 'Parâmetros instance e telefone são obrigatórios.' });
  }

  try {
    const query = `
      SELECT 1 FROM agent_customer_pauses
      WHERE instance_name = $1 AND telefone = $2 AND paused_until > NOW();
    `;
    const result = await pool.query(query, [instanceName, telefone]);
    const pausado = result.rows.length > 0;

    return res.status(200).json({ pausado });
  } catch (error) {
    console.error('Erro ao buscar status de pausa:', error);
    return res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

/**
 * POST /v1/tenant/pause
 * Insere ou remove a pausa de IA para um cliente específico de um inquilino
 */
app.post('/v1/tenant/pause', authenticateInternalToken, async (req: Request, res: Response) => {
  const { instance, telefone, paused, minutes } = req.body;

  if (!instance || !telefone) {
    return res.status(400).json({ error: 'Os campos instance e telefone são obrigatórios.' });
  }

  try {
    if (paused) {
      const min = minutes || 180; // Padrão: 3 horas
      const pausedUntil = new Date(Date.now() + min * 60 * 1000);

      const query = `
        INSERT INTO agent_customer_pauses (instance_name, telefone, paused_until)
        VALUES ($1, $2, $3)
        ON CONFLICT (instance_name, telefone)
        DO UPDATE SET paused_until = EXCLUDED.paused_until;
      `;
      await pool.query(query, [instance, telefone, pausedUntil]);

      console.log(`[v1 Pause] Instância ${instance} - Cliente ${telefone} PAUSADO até ${pausedUntil.toISOString()}`);

      return res.status(200).json({
        success: true,
        confirmacao: `Robô desativado por 3 horas nesta conversa. ⏸️`
      });
    } else {
      const query = `
        DELETE FROM agent_customer_pauses
        WHERE instance_name = $1 AND telefone = $2;
      `;
      await pool.query(query, [instance, telefone]);

      console.log(`[v1 Pause] Instância ${instance} - Cliente ${telefone} REATIVADO.`);

      return res.status(200).json({
        success: true,
        confirmacao: `Robô reativado com sucesso! 🔛`
      });
    }
  } catch (error) {
    console.error('Erro ao salvar pausa:', error);
    return res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

/**
 * POST /v1/tenant/cleanup-pauses
 * Limpa pausas de clientes expiradas do banco
 */
app.post('/v1/tenant/cleanup-pauses', authenticateInternalToken, async (req: Request, res: Response) => {
  try {
    const query = `
      DELETE FROM agent_customer_pauses
      WHERE paused_until <= NOW();
    `;
    const result = await pool.query(query);
    console.log(`[Cleanup Pauses] ${result.rowCount ?? 0} pausas expiradas removidas.`);
    return res.status(200).json({ success: true, count: result.rowCount ?? 0 });
  } catch (error) {
    console.error('Erro no cleanup de pausas:', error);
    return res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// Inicializar o servidor
app.listen(port, () => {
  console.log(`[Atendja Backend] Rodando com sucesso em http://localhost:${port}`);
});
