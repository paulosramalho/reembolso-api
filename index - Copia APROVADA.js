require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'reembolso-super-secreto';

app.use(cors());
app.use(express.json());

// --------- Upload de arquivos (NF / Comprovantes) ---------
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname || '');
    cb(null, unique + ext);
  },
});

const upload = multer({ storage });

// --------- Nodemailer (para reset de senha) ----------
let mailTransporter = null;

if (process.env.SMTP_HOST) {
  mailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: process.env.SMTP_USER
      ? {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        }
      : undefined,
  });

  mailTransporter.verify().then(
    () => {
      console.log('SMTP pronto para envio de e-mails de redefinição de senha.');
    },
    (err) => {
      console.error('Falha ao verificar SMTP:', err);
      mailTransporter = null;
    }
  );
} else {
  console.warn(
    '[AVISO] SMTP_HOST não definido. Links de redefinição serão apenas logados no console.'
  );
}

// --------- Middleware de autenticação ----------
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token não informado' });

  const [, token] = authHeader.split(' ');
  if (!token) return res.status(401).json({ error: 'Token inválido' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, nome, email, tipo }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// --------- Rotas de autenticação ----------

// Registrar usuário (pode ser só para você criar os primeiros)
app.post('/auth/register', async (req, res) => {
  try {
    const { nome, email, senha, tipo } = req.body;

    if (!nome || !email || !senha) {
      return res.status(400).json({ error: 'Nome, email e senha são obrigatórios.' });
    }

    const userExists = await db.query('SELECT id FROM usuarios WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'E-mail já cadastrado.' });
    }

    const senhaHash = await bcrypt.hash(senha, 10);
    const userTipo = tipo && ['admin', 'user'].includes(tipo) ? tipo : 'user';

    const result = await db.query(
      `INSERT INTO usuarios (nome, email, senha_hash, tipo)
       VALUES ($1, $2, $3, $4)
       RETURNING id, nome, email, tipo`,
      [nome, email, senhaHash, userTipo]
    );

    const user = result.rows[0];
    return res.status(201).json(user);
  } catch (err) {
    console.error('Erro em /auth/register:', err);
    return res.status(500).json({ error: 'Erro interno ao registrar usuário.' });
  }
});

// Login (aceita e-mail OU nome no campo "email" do body)
app.post('/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) {
      return res.status(400).json({ error: 'Email (ou nome) e senha são obrigatórios.' });
    }

    const login = email.trim();

    const result = await db.query(
      `SELECT id, nome, email, senha_hash, tipo, ativo, cpfcnpj, telefone
       FROM usuarios
       WHERE email = $1 OR nome = $1
       LIMIT 1`,
      [login]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
    }

    const user = result.rows[0];

    if (!user.ativo) {
      return res.status(403).json({ error: 'Usuário inativo.' });
    }

    const senhaConfere = await bcrypt.compare(senha, user.senha_hash);
    if (!senhaConfere) {
      return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
    }

    // Detecta se ainda está usando senha padrão
    const senhaPadrao = '12345';
    const usandoSenhaPadrao = await bcrypt.compare(senhaPadrao, user.senha_hash);

    const payload = {
      id: user.id,
      nome: user.nome,
      email: user.email,
      tipo: user.tipo,
      cpfcnpj: user.cpfcnpj,
      telefone: user.telefone,
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

    return res.json({
      token,
      user: payload,
      primeiroAcesso: usandoSenhaPadrao && senha === senhaPadrao,
    });
  } catch (err) {
    console.error('Erro em /auth/login:', err);
    return res.status(500).json({ error: 'Erro interno ao fazer login.' });
  }
});

// Troca de senha (inclui fluxo de primeiro acesso)
// Espera: { id, senhaAtual, novaSenha }
app.post('/auth/alterar-senha', authMiddleware, async (req, res) => {
  try {
    const { id } = req.user; // pega do token
    const { senhaAtual, novaSenha } = req.body;

    if (!senhaAtual || !novaSenha) {
      return res.status(400).json({
        error: 'Informe senha atual e nova senha.',
      });
    }

    const result = await db.query(
      `SELECT id, senha_hash FROM usuarios WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    const user = result.rows[0];

    const senhaConfere = await bcrypt.compare(senhaAtual, user.senha_hash);
    if (!senhaConfere) {
      return res.status(401).json({ error: 'Senha atual incorreta.' });
    }

    const novaHash = await bcrypt.hash(novaSenha, 10);

    await db.query(
      `UPDATE usuarios
       SET senha_hash = $1
       WHERE id = $2`,
      [novaHash, id]
    );

    return res.status(200).json({ message: 'Senha alterada com sucesso.' });
  } catch (err) {
    console.error('Erro em /auth/alterar-senha:', err);
    return res.status(500).json({ error: 'Erro ao alterar senha.' });
  }
});

// Fluxo "Esqueci minha senha": gera token e envia link por e-mail
// Espera: { email }
app.post('/auth/esqueci-senha', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res
        .status(400)
        .json({ error: 'Informe o e-mail (User ID) para redefinir a senha.' });
    }

    const login = email.trim();

    const result = await db.query(
      `SELECT id, email, ativo
       FROM usuarios
       WHERE email = $1 OR nome = $1
       LIMIT 1`,
      [login]
    );

    // Resposta SEM revelar se o usuário existe ou não
    const genericResponse = {
      message:
        'Se o usuário existir e estiver ativo, enviamos um e-mail com o link para redefinição de senha.',
    };

    if (result.rows.length === 0) {
      // não diz se existe ou não
      return res.json(genericResponse);
    }

    const user = result.rows[0];

    if (!user.ativo) {
      // também não revela que está inativo
      return res.json(genericResponse);
    }

    // Gera token randômico e expira em 1h
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1h

    await db.query(
      `UPDATE usuarios
       SET reset_token = $1,
           reset_token_expires = $2
       WHERE id = $3`,
      [resetToken, expiresAt, user.id]
    );

    const appBase = (process.env.APP_BASE_URL || 'http://localhost:5173').replace(/\/+$/, '');
    const resetLink = `${appBase}/login?resetToken=${encodeURIComponent(
      resetToken
    )}&email=${encodeURIComponent(user.email)}`;

    // Envia e-mail se SMTP configurado, senão loga no console (dev)
    if (mailTransporter) {
      try {
        await mailTransporter.sendMail({
          from: process.env.MAIL_FROM || 'no-reply@reembolso.local',
          to: user.email,
          subject: 'Redefinição de senha - Controle de Reembolso',
          text: [
            'Você solicitou a redefinição da sua senha no Controle de Reembolso.',
            'Se você não fez essa solicitação, ignore este e-mail.',
            '',
            `Para redefinir sua senha, acesse o link abaixo (válido por 1 hora):`,
            resetLink,
          ].join('\n'),
          html: `
            <p>Você solicitou a redefinição da sua senha no <strong>Controle de Reembolso</strong>.</p>
            <p>Se você não fez essa solicitação, ignore este e-mail.</p>
            <p>Para redefinir sua senha, clique no link abaixo (válido por 1 hora):</p>
            <p><a href="${resetLink}">${resetLink}</a></p>
          `,
        });
      } catch (mailErr) {
        console.error('Erro ao enviar e-mail de redefinição:', mailErr);
        // mesmo se o e-mail falhar, não expomos pro usuário
      }
    } else {
      // 👉 ESTE BLOCO GARANTE O LOG NO CONSOLE EM DEV
      console.log('\n*** Link de redefinição de senha ***');
      console.log(resetLink);
      console.log('************************************\n');
    }

    return res.json(genericResponse);
  } catch (err) {
    console.error('Erro em /auth/esqueci-senha:', err);
    return res
      .status(500)
      .json({ error: 'Erro ao iniciar fluxo de redefinição de senha.' });
  }
});


// Aplica nova senha a partir de um token de redefinição
// Espera: { token, novaSenha }
app.post('/auth/reset-senha', async (req, res) => {
  try {
    const { token, novaSenha } = req.body;

    if (!token || !novaSenha) {
      return res
        .status(400)
        .json({ error: 'Token e nova senha são obrigatórios.' });
    }

    if (novaSenha.length < 4) {
      return res
        .status(400)
        .json({ error: 'Use uma senha com pelo menos 4 caracteres.' });
    }

    const result = await db.query(
      `SELECT id, reset_token_expires
       FROM usuarios
       WHERE reset_token = $1
       LIMIT 1`,
      [token]
    );

    if (result.rows.length === 0) {
      return res
        .status(401)
        .json({ error: 'Token inválido ou já utilizado para redefinição.' });
    }

    const user = result.rows[0];

    if (
      !user.reset_token_expires ||
      new Date(user.reset_token_expires).getTime() < Date.now()
    ) {
      return res
        .status(401)
        .json({ error: 'Token expirado para redefinição de senha.' });
    }

    const novaHash = await bcrypt.hash(novaSenha, 10);

    await db.query(
      `UPDATE usuarios
       SET senha_hash = $1,
           reset_token = NULL,
           reset_token_expires = NULL
       WHERE id = $2`,
      [novaHash, user.id]
    );

    return res.json({ message: 'Senha redefinida com sucesso.' });
  } catch (err) {
    console.error('Erro em /auth/reset-senha:', err);
    return res
      .status(500)
      .json({ error: 'Erro ao concluir redefinição de senha.' });
  }
});

// ⚠️ ROTA SOMENTE PARA DESENVOLVIMENTO
// Obtém o link de redefinição com base no e-mail
app.get('/auth/reset-link-dev', async (req, res) => {
  try {
    const { email } = req.query;

    if (!email) {
      return res.status(400).json({ error: 'Informe o e-mail na query string ?email=' });
    }

    const result = await db.query(
      `SELECT id, email, reset_token, reset_token_expires
       FROM usuarios
       WHERE email = $1
       LIMIT 1`,
      [email.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    const user = result.rows[0];

    if (!user.reset_token) {
      return res.status(400).json({
        error: 'Usuário não possui reset_token. Inicie o fluxo de "Esqueci minha senha" primeiro.',
      });
    }

    if (
      !user.reset_token_expires ||
      new Date(user.reset_token_expires).getTime() < Date.now()
    ) {
      return res.status(400).json({
        error: 'Token expirado. Refaça o fluxo de "Esqueci minha senha".',
      });
    }

    const appBase = (process.env.APP_BASE_URL || 'http://localhost:5173').replace(/\/+$/, '');
    const resetLink = `${appBase}/login?resetToken=${encodeURIComponent(
      user.reset_token
    )}&email=${encodeURIComponent(user.email)}`;

    return res.json({ resetLink });
  } catch (err) {
    console.error('Erro em GET /auth/reset-link-dev:', err);
    return res.status(500).json({ error: 'Erro ao recuperar link de redefinição.' });
  }
});

// --------- Usuários (Configurações) ----------

// Lista todos os usuários para a tela de Configurações
app.get('/usuarios', authMiddleware, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT
         id,
         nome,
         email,
         tipo,
         ativo,
         cpfcnpj AS "cpfcnpj",
         telefone
       FROM usuarios
       ORDER BY id ASC`
    );

    return res.json(result.rows);
  } catch (err) {
    console.error('Erro em GET /usuarios:', err);
    return res.status(500).json({ error: 'Erro ao listar usuários.' });
  }
});

// Cria um novo usuário "solicitante" a partir da Configuração
app.post('/usuarios', authMiddleware, async (req, res) => {
  try {
    const { nome, email, tipo, cpf, cpfcnpj, telefone } = req.body;

    if (!nome || !email) {
      return res
        .status(400)
        .json({ error: 'Nome e e-mail são obrigatórios.' });
    }

    // Garante que não exista e-mail duplicado
    const userExists = await db.query(
      'SELECT id FROM usuarios WHERE email = $1',
      [email]
    );
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'E-mail já cadastrado.' });
    }

    // Define tipo padrão
    const userTipo =
      tipo && ['admin', 'user'].includes(String(tipo).toLowerCase())
        ? String(tipo).toLowerCase()
        : 'user';

    // Documento: tenta cpfcnpj, depois cpf
    const doc = (cpfcnpj || cpf || '').trim() || null;

    // Senha padrão
    const senhaPadrao = '12345';
    const senhaHash = await bcrypt.hash(senhaPadrao, 10);

    const result = await db.query(
      `INSERT INTO usuarios (nome, email, senha_hash, tipo, ativo, cpfcnpj, telefone)
       VALUES ($1, $2, $3, $4, true, $5, $6)
       RETURNING id, nome, email, tipo, ativo, cpfcnpj AS "cpfcnpj", telefone`,
      [nome, email, senhaHash, userTipo, doc, telefone || null]
    );

    return res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro em POST /usuarios:', err);
    return res.status(500).json({ error: 'Erro ao criar usuário.' });
  }
});

// Busca um usuário específico (para tela "Meu Perfil")
app.get('/usuarios/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await db.query(
      `SELECT
         id,
         nome,
         email,
         tipo,
         ativo,
         cpfcnpj,
         telefone
       FROM usuarios
       WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    const user = result.rows[0];

    return res.json({
      id: user.id,
      nome: user.nome,
      email: user.email,
      tipo: user.tipo,
      ativo: user.ativo,
      cpfcnpj: user.cpfcnpj,
      telefone: user.telefone,
    });
  } catch (err) {
    console.error('Erro em GET /usuarios/:id:', err);
    return res
      .status(500)
      .json({ error: 'Erro ao buscar dados do usuário.' });
  }
});

// Atualiza um usuário existente (nome, e-mail, tipo, ativo, cpfcnpj, telefone)
app.patch('/usuarios/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { nome, email, tipo, ativo, cpf, cpfcnpj, telefone } = req.body;

    // Busca atual
    const current = await db.query(
      'SELECT * FROM usuarios WHERE id = $1',
      [id]
    );

    if (current.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    const u = current.rows[0];

    const newNome = nome ?? u.nome;
    const newEmail = email ?? u.email;
    const newTipo = tipo ?? u.tipo;
    const newAtivo = typeof ativo === 'boolean' ? ativo : u.ativo;
    // 🔎 Regra para CPF/CNPJ:
    // - Se o front MANDAR cpf/cpfcnpj (mesmo que null ou ""), usamos o que veio.
    //   - "" → vira null → LIMPA o campo no banco.
    // - Se o front NÃO mandar nada (undefined), mantemos o valor antigo.
    let newDoc;
    if (typeof cpfcnpj !== 'undefined' || typeof cpf !== 'undefined') {
      const raw = (cpfcnpj ?? cpf ?? '').toString().trim();
      newDoc = raw || null; // vazio => null
    } else {
      newDoc = u.cpfcnpj;
    }

    const newTelefone = telefone ?? u.telefone;

    const result = await db.query(
      `UPDATE usuarios
       SET
         nome      = $1,
         email     = $2,
         tipo      = $3,
         ativo     = $4,
         cpfcnpj   = $5,
         telefone  = $6
       WHERE id = $7
       RETURNING id, nome, email, tipo, ativo, cpfcnpj AS "cpfcnpj", telefone`,
      [newNome, newEmail, newTipo, newAtivo, newDoc, newTelefone, id]
    );

    return res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro em PATCH /usuarios/:id', err);
    return res.status(500).json({ error: 'Erro ao atualizar usuário.' });
  }
});

// Remove um usuário (se não estiver sendo referenciado por FK, etc.)
app.delete('/usuarios/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    await db.query('DELETE FROM usuarios WHERE id = $1', [id]);
    return res.status(204).send();
  } catch (err) {
    console.error('Erro em DELETE /usuarios/:id:', err);
    return res.status(500).json({ error: 'Erro ao excluir usuário.' });
  }
});

// Quem sou eu (útil pro front validar sessão)
app.get('/auth/me', authMiddleware, (req, res) => {
  return res.json({ user: req.user });
});


// --------- Rotas de solicitações ----------

// Listar solicitações
app.get('/solicitacoes', authMiddleware, async (req, res) => {
  try {
    const { id, tipo } = req.user;
    const params = [];

    // 🔹 Normaliza o tipo em minúsculas
    const tipoNorm = String(tipo || '').toLowerCase();
    const isAdmin = tipoNorm === 'admin' || tipoNorm === 'adm';

    let queryBase = `
      SELECT
        s.*,
        u.nome    AS usuario_nome,
        u.email   AS usuario_email,
        u.cpfcnpj AS cpfcnpj,
        (
          SELECT COUNT(*)::int
          FROM solicitacao_arquivos a
          WHERE a.solicitacao_id = s.id
        ) AS "docsExtrasCount"
      FROM solicitacoes s
      JOIN usuarios u ON u.id = s.usuario_id
    `;

    if (isAdmin) {
      // 🔓 Admin enxerga TUDO
      queryBase += ` ORDER BY s.id DESC`;
    } else {
      // 👤 Usuário comum enxerga apenas o que é dele
      queryBase += `
        WHERE s.usuario_id = $1
        ORDER BY s.id DESC
      `;
      params.push(id);
    }

    const result = await db.query(queryBase, params);
    const rows = result.rows;

    // Histórico (mantido igual)
    try {
      for (const row of rows) {
        const histRes = await db.query(
          `SELECT status, data AS date, origem, obs
           FROM solicitacao_status_history
           WHERE solicitacao_id = $1
           ORDER BY data`,
          [row.id]
        );
        row.status_history = histRes.rows;
      }
    } catch (err) {
      for (const row of rows) row.status_history = [];
    }

    return res.json(rows);
  } catch (err) {
    console.error('Erro em GET /solicitacoes:', err);
    return res.status(500).json({ error: 'Erro ao listar solicitações.' });
  }
});


// Criar nova solicitação (já grava o status inicial no histórico)
app.post('/solicitacoes', authMiddleware, async (req, res) => {
  try {
    // usuário logado (para fallback / auditoria)
    const { id: usuarioLogadoId } = req.user;

    const {
      usuario_id,       // 👈 id do solicitante vindo do front (Nova.jsx)
      solicitante_id,   // 👈 se em algum momento vier com outro nome
      solicitante_nome,
      beneficiario_nome,
      beneficiario_doc,
      numero_nf,
      data_nf,
      valor_nf,
      emitente_nome,
      emitente_doc,
      status,
      protocolo,
      nr_protocolo,
      numero_protocolo,
      valor,
      valor_solicitado,
      data_solicitacao,
      data,
      descricao   // 👈 descrição da despesa
    } = req.body;

    // --- Definição do DONO da solicitação (sempre o selecionado) ---
    const tryParseId = (v) => {
      const n = Number(v);
      return Number.isFinite(n) && n > 0 ? n : null;
    };

    // prioridade: usuario_id > solicitante_id > id do usuário logado
    const usuarioDonoId =
      tryParseId(usuario_id) ??
      tryParseId(solicitante_id) ??
      usuarioLogadoId;

    // --- Demais campos, como já estavam ---

    const protocoloFinal =
      protocolo || nr_protocolo || numero_protocolo || null;

    // Data da solicitação vinda do front
    const dataSolicFinal = data_solicitacao || data || new Date();

    const valorFinal =
      (valor_solicitado ?? valor ?? valor_nf) ?? null;

    const statusInicial = status || 'Em análise';

    const insertResult = await db.query(
      `INSERT INTO solicitacoes (
        usuario_id,
        solicitante_nome,
        beneficiario_nome,
        beneficiario_doc,
        numero_nf,
        data_nf,
        valor_nf,
        emitente_nome,
        emitente_doc,
        status,
        protocolo,
        data_solicitacao,
        valor,
        descricao
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      RETURNING *`,
      [
        usuarioDonoId,                      // 👈 AGORA É SEMPRE O SELECIONADO
        solicitante_nome || null,
        beneficiario_nome || null,
        beneficiario_doc || null,
        numero_nf || null,
        data_nf || null,
        valor_nf || null,
        emitente_nome || null,
        emitente_doc || null,
        statusInicial,
        protocoloFinal,
        dataSolicFinal,
        valorFinal,
        descricao || null
      ]
    );

    const created = insertResult.rows[0];

    // Histórico inicial do status (mantido igual)
    try {
      const dataHist =
        data_solicitacao ||
        new Date();

      await db.query(
        `INSERT INTO solicitacao_status_history (
          solicitacao_id,
          status,
          data,
          origem,
          obs
        ) VALUES ($1,$2,$3,$4,$5)`,
        [
          created.id,
          statusInicial,
          dataHist,
          'Criação',
          'Status inicial da solicitação'
        ]
      );
    } catch (errHist) {
      console.error('🔥 ERRO AO INSERIR HISTÓRICO INICIAL:', errHist);
    }

    return res.status(201).json(created);
  } catch (err) {
    console.error('Erro em POST /solicitacoes:', err);
    return res.status(500).json({ error: 'Erro ao criar solicitação.' });
  }
});

// --------- Upload de arquivos vinculados à solicitação ----------

// rota de upload
// Exemplo: multer configurado antes
// const upload = multer({ dest: path.join(__dirname, 'uploads') })

// rota de upload de arquivos vinculados à solicitação
app.post(
  '/solicitacoes/:id/arquivos',
  authMiddleware,
  upload.single('file'), // 👈 TEM que ser 'file' para casar com o front
  async (req, res) => {
    try {
      const solicitacaoId = parseInt(req.params.id, 10);
      const { tipo: tipoUsuario, id: usuarioId } = req.user;
      const { tipo: tipoArquivo } = req.body;

      if (!Number.isFinite(solicitacaoId)) {
        return res.status(400).json({ error: 'Solicitação inválida.' });
      }

      if (!req.file) {
        return res.status(400).json({ error: 'Arquivo é obrigatório.' });
      }

      // 1) valida se a solicitação existe e pertence ao usuário (ou se é admin)
      let query = 'SELECT * FROM solicitacoes WHERE id = $1';
      const params = [solicitacaoId];

      if (String(tipoUsuario || '').toLowerCase() !== 'admin') {
        query += ' AND usuario_id = $2';
        params.push(usuarioId);
      }

      const existing = await db.query(query, params);

      if (existing.rows.length === 0) {
        return res.status(404).json({
          error: 'Solicitação não encontrada para este usuário.',
        });
      }

      // 2) salva metadados do arquivo na tabela solicitacao_arquivos
      const insert = await db.query(
        `INSERT INTO solicitacao_arquivos
           (solicitacao_id, tipo, original_name, mime_type, path)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING
           id, solicitacao_id, tipo, original_name, mime_type, path, created_at`,
        [
          solicitacaoId,
          tipoArquivo || 'EXTRA',           // default p/ docs extras
          req.file.originalname,
          req.file.mimetype,
          req.file.filename,                // nome físico no disco
        ]
      );

      return res.status(201).json(insert.rows[0]);
    } catch (err) {
      console.error('Erro em POST /solicitacoes/:id/arquivos:', err);
      return res
        .status(500)
        .json({ error: 'Erro ao salvar documento extra.' });
    }
  }
);

// rota serve arquivos estáticos
app.use('/uploads', express.static(uploadDir));

// Atualizar solicitação (e registrar cada troca de status no histórico)
app.put('/solicitacoes/:id', authMiddleware, async (req, res) => {
  const solId = Number(req.params.id);
  if (!Number.isFinite(solId)) {
    return res.status(400).json({ error: 'ID inválido.' });
  }

  try {
    const { id: usuarioId, tipo } = req.user;
    const tipoNorm = String(tipo || '').toLowerCase();

    // 1) Buscar registro atual + dono
    const existingResult = await db.query(
      'SELECT * FROM solicitacoes WHERE id = $1',
      [solId]
    );

    if (!existingResult.rows.length) {
      return res.status(404).json({ error: 'Solicitação não encontrada.' });
    }

    const existing = existingResult.rows[0];

    // 2) Se não for admin, só pode alterar o que é dele
    const isAdmin = tipoNorm === 'admin' || tipoNorm === 'adm';
    if (!isAdmin && existing.usuario_id !== usuarioId) {
      return res
        .status(403)
        .json({ error: 'Você não tem permissão para alterar esta solicitação.' });
    }

    // 3) Campos vindos do front
    const {
      status,
      protocolo,
      nr_protocolo,
      numero_protocolo,
      data_solicitacao,
      data,
      valor,
      valor_solicitado,
      statusDate,
      descricao,
      obs,
      dataPagamento,
      valorReembolso,
    } = req.body;

    // conversor seguro de valores
    const toNum = (x) => {
      if (typeof x === 'number') return Number.isFinite(x) ? x : null;
      if (typeof x === 'string' && x.trim()) {
        const n = Number(x.replace(/\./g, '').replace(',', '.'));
        return Number.isFinite(n) ? n : null;
      }
      return null;
    };

    // 4) Composições finais
    const prevStatus = existing.status;
    const statusFinal = status ?? prevStatus;

    const protocoloFinal =
      protocolo ||
      nr_protocolo ||
      numero_protocolo ||
      existing.protocolo ||
      null;

    const dataSolicFinal =
      data_solicitacao || data || existing.data_solicitacao || null;

    let valorFinal = toNum(valor);
    if (valorFinal == null) valorFinal = toNum(valor_solicitado);
    if (valorFinal == null) valorFinal = existing.valor;

    const descricaoFinal = descricao ?? existing.descricao ?? null;

    const dataPagamentoFinal = Object.prototype.hasOwnProperty.call(
      req.body,
      'dataPagamento'
    )
      ? dataPagamento
      : existing.data_pagamento;

    const valorReembolsoFinal =
      toNum(valorReembolso) ?? existing.valor_reembolso ?? null;

    // 5) Update principal (inclui pagamento)
    const updateResult = await db.query(
      `
      UPDATE solicitacoes
         SET status           = $1,
             protocolo        = $2,
             data_solicitacao = $3,
             valor            = $4,
             descricao        = $5,
             data_pagamento   = $6,
             valor_reembolso  = $7
       WHERE id = $8
       RETURNING *
      `,
      [
        statusFinal,
        protocoloFinal,
        dataSolicFinal,
        valorFinal,
        descricaoFinal,
        dataPagamentoFinal,
        valorReembolsoFinal,
        solId,
      ]
    );

    const updated = updateResult.rows[0];

    // ===== HISTÓRICO =====
    const mudouStatus = statusFinal !== prevStatus;

    let movDate =
      statusDate ||
      data_solicitacao ||
      new Date().toISOString().slice(0, 10);

    if (mudouStatus || statusDate) {
      await db.query(
        `
        INSERT INTO solicitacao_status_history
          (solicitacao_id, status, data, origem, obs)
        VALUES ($1, $2, $3, $4, $5)
        `,
        [solId, statusFinal, movDate, 'API', obs || null]
      );
    }

    return res.json(updated);
  } catch (err) {
    console.error('Erro em PUT /solicitacoes/:id', err);
    return res.status(500).json({ error: 'Erro ao atualizar solicitação.' });
  }
});

// Excluir solicitação + anexos vinculados
app.delete('/solicitacoes/:id', authMiddleware, async (req, res) => {
  try {
    const solId = parseInt(req.params.id, 10);

    if (Number.isNaN(solId)) {
      return res.status(400).json({ error: 'ID inválido.' });
    }

    const { id: usuarioId, tipo } = req.user;

    // 1) Buscar anexos antes de excluir a solicitação
    const anexosResult = await db.query(
      'SELECT path FROM solicitacao_arquivos WHERE solicitacao_id = $1',
      [solId]
    );
    const filePaths = anexosResult.rows
      .map((r) => r.path)
      .filter((p) => !!p);

    // 2) Excluir a solicitação (respeitando admin / user)
    let result;
    if (tipo === 'admin') {
      // admin pode excluir qualquer solicitação
      result = await db.query(
        'DELETE FROM solicitacoes WHERE id = $1 RETURNING id',
        [solId]
      );
    } else {
      // usuário comum só exclui o que é dele
      result = await db.query(
        'DELETE FROM solicitacoes WHERE id = $1 AND usuario_id = $2 RETURNING id',
        [solId, usuarioId]
      );
    }

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Solicitação não encontrada.' });
    }

    // 3) Apagar arquivos físicos vinculados
    // (as linhas em solicitacao_arquivos podem estar com ON DELETE CASCADE)
    for (const relPath of filePaths) {
      try {
        const fullPath = path.join(uploadDir, relPath);
        fs.unlink(fullPath, (err) => {
          if (err && err.code !== 'ENOENT') {
            console.error(
              'Erro ao remover arquivo de anexo:',
              fullPath,
              err
            );
          }
        });
      } catch (e) {
        console.error('Erro ao montar/remover caminho de anexo:', e);
      }
    }

    return res.status(204).send();
  } catch (err) {
    console.error('Erro em DELETE /solicitacoes/:id:', err);
    return res
      .status(500)
      .json({ error: 'Erro ao excluir solicitação.' });
  }
});

// Listar anexos (NF, comprovantes, extras) de uma solicitação
app.get('/solicitacoes/:id/arquivos', authMiddleware, async (req, res) => {
  try {
    const solId = parseInt(req.params.id, 10);
    if (Number.isNaN(solId)) {
      return res.status(400).json({ error: 'ID inválido.' });
    }

    const { id: usuarioId, tipo } = req.user;

    let query = `
      SELECT
        a.id,
        a.tipo,
        a.original_name,
        a.mime_type,
        a.path,
        a.created_at
      FROM solicitacao_arquivos a
      JOIN solicitacoes s ON s.id = a.solicitacao_id
      WHERE a.solicitacao_id = $1
    `;
    const params = [solId];

    if (tipo !== 'admin') {
      query += ' AND s.usuario_id = $2';
      params.push(usuarioId);
    }

    const result = await db.query(query, params);

    // devolve também a URL pra download
    const base =
      process.env.PUBLIC_API_BASE ||
      ''; // opcional, se quiser; se não, usamos relativo
    const rows = result.rows.map((r) => ({
      ...r,
      url: `${base}/uploads/${r.path}`,
    }));

    return res.json(rows);
  } catch (err) {
    console.error('Erro em GET /solicitacoes/:id/arquivos:', err);
    return res
      .status(500)
      .json({ error: 'Erro ao listar anexos da solicitação.' });
  }
});


// ===================== DESCRICOES ======================
app.get('/descricoes', authMiddleware, async (req, res) => {
  try {
    const r = await db.query(
      `SELECT id, descricao, ativo
       FROM descricoes
       ORDER BY id ASC`
    );
    res.json(r.rows);
  } catch (err) {
    console.error('Erro GET /descricoes:', err);
    res.status(500).json({ error: 'Erro ao listar descrições.' });
  }
});

app.post('/descricoes', authMiddleware, async (req, res) => {
  try {
    const { descricao, ativo } = req.body;

    const r = await db.query(
      `INSERT INTO descricoes (descricao, ativo)
       VALUES ($1,$2)
       RETURNING id, descricao, ativo`,
      [descricao, ativo ?? true]
    );

    res.status(201).json(r.rows[0]);
  } catch (err) {
    console.error('Erro POST /descricoes:', err);
    res.status(500).json({ error: 'Erro ao criar descrição.' });
  }
});

app.patch('/descricoes/:id', authMiddleware, async (req, res) => {
  try {
    const { descricao, ativo } = req.body;
    const id = req.params.id;

    const r = await db.query(
      `UPDATE descricoes
       SET descricao = COALESCE($1, descricao),
           ativo = COALESCE($2, ativo)
       WHERE id = $3
       RETURNING id, descricao, ativo`,
      [descricao, ativo, id]
    );

    res.json(r.rows[0]);
  } catch (err) {
    console.error('Erro PATCH /descricoes/:id:', err);
    res.status(500).json({ error: 'Erro ao atualizar descrição.' });
  }
});

app.delete('/descricoes/:id', authMiddleware, async (req, res) => {
  try {
    const id = req.params.id;

    await db.query(`DELETE FROM descricoes WHERE id = $1`, [id]);

    res.status(204).send();
  } catch (err) {
    console.error('Erro DELETE /descricoes/:id:', err);
    res.status(500).json({ error: 'Erro ao excluir descrição.' });
  }
});

// ===================== STATUS ======================
app.get('/status', authMiddleware, async (req, res) => {
  try {
    const r = await db.query(
      `SELECT id, nome AS descricao, ativo
       FROM status
       ORDER BY id ASC`
    );
    res.json(r.rows);
  } catch (err) {
    console.error('Erro GET /status:', err);
    res.status(500).json({ error: 'Erro ao listar status.' });
  }
});

app.post('/status', authMiddleware, async (req, res) => {
  try {
    const { nome, descricao, ativo } = req.body;

    const r = await db.query(
      `INSERT INTO status (nome, ativo)
       VALUES ($1,$2)
       RETURNING id, nome AS descricao, ativo`,
      [descricao || nome, ativo ?? true]
    );

    res.status(201).json(r.rows[0]);
  } catch (err) {
    console.error('Erro POST /status:', err);
    res.status(500).json({ error: 'Erro ao criar status.' });
  }
});

app.patch('/status/:id', authMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    const { descricao, ativo } = req.body;

    const r = await db.query(
      `UPDATE status
       SET nome = COALESCE($1, nome),
           ativo = COALESCE($2, ativo)
       WHERE id = $3
       RETURNING id, nome AS descricao, ativo`,
      [descricao, ativo, id]
    );

    res.json(r.rows[0]);
  } catch (err) {
    console.error('Erro PATCH /status/:id:', err);
    res.status(500).json({ error: 'Erro ao atualizar status.' });
  }
});

app.delete('/status/:id', authMiddleware, async (req, res) => {
  try {
    const id = req.params.id;

    await db.query(`DELETE FROM status WHERE id = $1`, [id]);

    res.status(204).send();
  } catch (err) {
    console.error('Erro DELETE /status/:id:', err);
    res.status(500).json({ error: 'Erro ao excluir status.' });
  }
});

// Limpar TODOS os anexos da nuvem (admin only)
// Use APENAS na virada para produção
app.delete('/anexos', authMiddleware, async (req, res) => {
  try {
    const { tipo } = req.user;
    if (tipo !== 'admin') {
      return res
        .status(403)
        .json({ error: 'Apenas administradores podem limpar anexos.' });
    }

    const result = await db.query(
      'SELECT path FROM solicitacao_arquivos'
    );
    const files = result.rows.map((r) => r.path).filter(Boolean);

    // apaga registros
    await db.query('DELETE FROM solicitacao_arquivos');

    // tenta apagar arquivos físicos
    for (const relPath of files) {
      try {
        const fullPath = path.join(uploadDir, relPath);
        fs.unlink(fullPath, (err) => {
          if (err && err.code !== 'ENOENT') {
            console.error(
              'Erro ao remover arquivo em limpeza geral:',
              fullPath,
              err
            );
          }
        });
      } catch (e) {
        console.error(
          'Erro ao montar/remover caminho em limpeza geral:',
          e
        );
      }
    }

    return res.status(204).send();
  } catch (err) {
    console.error('Erro em DELETE /anexos:', err);
    return res
      .status(500)
      .json({ error: 'Erro ao limpar anexos da nuvem.' });
  }
});

// --------- Estrutura dinâmica do banco (TXT) ----------
app.get('/maintenance/schema-txt', authMiddleware, async (req, res) => {
  try {
    const tipo = String(req.user?.tipo || '').toLowerCase();
    if (tipo !== 'admin') {
      return res
        .status(403)
        .json({ error: 'Apenas administradores podem gerar a estrutura do banco.' });
    }

    const result = await db.query(
      `
      SELECT
        table_name,
        column_name,
        data_type,
        is_nullable,
        column_default,
        character_maximum_length,
        ordinal_position
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name NOT LIKE 'pg_%'
        AND table_name NOT LIKE 'sql_%'
      ORDER BY table_name, ordinal_position
      `
    );

    const rows = result.rows || [];
    const lines = [];

    const now = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    const headerDate = `${pad(now.getDate())}/${pad(
      now.getMonth() + 1
    )}/${now.getFullYear()} ${pad(now.getHours())}:${pad(now.getMinutes())}`;

    lines.push('Controle de Reembolso – Estrutura de Banco de Dados (gerado automaticamente)');
    lines.push(`Gerado em: ${headerDate}`);
    lines.push('');

    if (!rows.length) {
      lines.push('Nenhuma coluna encontrada no schema public.');
    } else {
      let currentTable = null;

      for (const col of rows) {
        if (col.table_name !== currentTable) {
          currentTable = col.table_name;
          lines.push('');
          lines.push(`TABELA ${currentTable}`);
        }

        const nullable = col.is_nullable === 'YES' ? 'NULL' : 'NOT NULL';

        let type = col.data_type;
        if (col.character_maximum_length) {
          type += `(${col.character_maximum_length})`;
        }

        let def = '';
        if (col.column_default) {
          def = ` DEFAULT ${col.column_default}`;
        }

        lines.push(`- ${col.column_name} ${type} ${nullable}${def}`.trim());
      }

      lines.push('');
      lines.push(
        'Obs.: Estrutura gerada automaticamente a partir de information_schema.columns (schema public).'
      );
    }

    const text = lines.join('\n');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.send(text);
  } catch (err) {
    console.error('Erro em GET /maintenance/schema-txt:', err);
    return res.status(500).json({ error: 'Erro ao gerar estrutura do banco.' });
  }
});

// --------- Healthcheck ----------
app.get('/', (req, res) => {
  res.send('API Reembolso rodando.');
});

// --------- Start ----------
app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT}`);
});
