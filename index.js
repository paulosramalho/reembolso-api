require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

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
      telefone: user.telefone
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

    return res.json({
      token,
      user: payload,
      primeiroAcesso: usandoSenhaPadrao && senha === senhaPadrao
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
        error: 'Informe senha atual e nova senha.'
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

// Fluxo "Esqueci minha senha": emite token temporário (por e-mail)
// Espera: { email }
app.post('/auth/esqueci-senha', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res
        .status(400)
        .json({ error: 'Informe o e-mail para redefinir a senha.' });
    }

    const login = email.trim().toLowerCase();

    const result = await db.query(
      `SELECT id, email, ativo
       FROM usuarios
       WHERE LOWER(email) = $1
       LIMIT 1`,
      [login]
    );

    // Resposta SEMPRE genérica, mesmo se não existir/for inativo
    if (result.rows.length === 0 || result.rows[0].ativo === false) {
      return res.json({
        message:
          'Se o usuário existir e estiver ativo, você receberá um e-mail com as instruções para redefinir a senha.'
      });
    }

    const user = result.rows[0];

    // Gera token JWT específico para reset de senha (1h)
    const resetToken = jwt.sign(
      {
        sub: user.id,
        purpose: 'reset-password',
      },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Base do app para montar o link (pode vir do .env)
    const APP_BASE =
      process.env.PUBLIC_APP_BASE ||
      process.env.APP_BASE_URL ||
      'http://localhost:5173';

    const resetUrl = `${APP_BASE}/login?reset=${encodeURIComponent(
      resetToken
    )}&email=${encodeURIComponent(user.email)}`;

    // Aqui seria o envio de e-mail de verdade.
    // Por enquanto, apenas loga no servidor (ambiente de desenvolvimento):
    console.log('🔐 Link de redefinição de senha gerado para', user.email);
    console.log('👉', resetUrl);

    // Resposta genérica segura
    return res.json({
      message:
        'Se o usuário existir e estiver ativo, você receberá um e-mail com as instruções para redefinir a senha.'
    });
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

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res
        .status(401)
        .json({ error: 'Token inválido ou expirado para redefinição.' });
    }

    if (!decoded || decoded.purpose !== 'reset-password' || !decoded.sub) {
      return res
        .status(401)
        .json({ error: 'Token inválido para redefinição de senha.' });
    }

    const userId = decoded.sub;

    const novaHash = await bcrypt.hash(novaSenha, 10);

    await db.query(
      `UPDATE usuarios
       SET senha_hash = $1
       WHERE id = $2`,
      [novaHash, userId]
    );

    return res.json({ message: 'Senha redefinida com sucesso.' });
  } catch (err) {
    console.error('Erro em /auth/reset-senha:', err);
    return res
      .status(500)
      .json({ error: 'Erro ao concluir redefinição de senha.' });
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

// Busca um usuário específico (para "Meu Perfil")
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
         cpfcnpj AS "cpfcnpj",
         telefone
       FROM usuarios
       WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    return res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro em GET /usuarios/:id:', err);
    return res.status(500).json({ error: 'Erro ao buscar usuário.' });
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

    const
