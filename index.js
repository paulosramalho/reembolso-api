require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'reembolso-super-secreto';

app.use(cors());
app.use(express.json());

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

// Login
// Login (aceita e-mail OU nome no campo "email" do body)
app.post('/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) {
      return res.status(400).json({ error: 'Email (ou nome) e senha são obrigatórios.' });
    }

    const login = email.trim();

    const result = await db.query(
      `SELECT id, nome, email, senha_hash, tipo, ativo, cpfCnpj, telefone
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
      cpfCnpj: user.cpfcnpj,
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


// --------- Usuários (Configurações) ----------

// Lista todos os usuários para a tela de Configurações
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
         cpfCnpj AS "cpfCnpj",
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
// Cria um novo usuário "solicitante" a partir da Configuração
app.post('/usuarios', authMiddleware, async (req, res) => {
  try {
    const { nome, email, tipo, cpf, cpfCnpj, telefone } = req.body;

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

    // Documento: tenta cpfCnpj, depois cpf
    const doc = (cpfCnpj || cpf || '').trim() || null;

    // Senha padrão que você quer usar
    const senhaPadrao = '12345';
    const senhaHash = await bcrypt.hash(senhaPadrao, 10);

    const result = await db.query(
      `INSERT INTO usuarios (nome, email, senha_hash, tipo, ativo, cpfCnpj, telefone)
       VALUES ($1, $2, $3, $4, true, $5, $6)
          RETURNING id, nome, email, tipo, ativo, cpfCnpj AS "cpfCnpj", telefone`,
      [nome, email, senhaHash, userTipo, doc, telefone || null]
    );

    return res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro em POST /usuarios:', err);
    return res.status(500).json({ error: 'Erro ao criar usuário.' });
  }
});


// Atualiza um usuário existente (nome, e-mail, tipo, ativo)
// Atualiza um usuário existente (nome, e-mail, tipo, ativo, cpfCnpj, telefone)
app.patch('/usuarios/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { nome, email, tipo, ativo, cpf, cpfCnpj, telefone } = req.body;

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
    const newDoc = (cpfCnpj || cpf || u.cpfcnpj || '').trim() || null;
    const newTelefone = telefone ?? u.telefone;

    const result = await db.query(
      `UPDATE usuarios
       SET
         nome      = $1,
         email     = $2,
         tipo      = $3,
         ativo     = $4,
         cpfCnpj   = $5,
         telefone  = $6
       WHERE id = $7
          RETURNING id, nome, email, tipo, ativo, cpfCnpj AS "cpfCnpj", telefone`,
      [newNome, newEmail, newTipo, newAtivo, newDoc, newTelefone, id]
    );

    return res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro em PATCH /usuarios/:id:', err);
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

    let result;
    if (tipo === 'admin') {
      result = await db.query(
        `SELECT s.*, u.nome AS usuario_nome, u.email AS usuario_email
         FROM solicitacoes s
         JOIN usuarios u ON u.id = s.usuario_id
         ORDER BY s.id DESC`
      );
    } else {
      result = await db.query(
        `SELECT s.*, u.nome AS usuario_nome, u.email AS usuario_email
         FROM solicitacoes s
         JOIN usuarios u ON u.id = s.usuario_id
         WHERE s.usuario_id = $1
         ORDER BY s.id DESC`,
        [id]
      );
    }

    return res.json(result.rows);
  } catch (err) {
    console.error('Erro em GET /solicitacoes:', err);
    return res.status(500).json({ error: 'Erro ao listar solicitações.' });
  }
});

// Criar nova solicitação
app.post('/solicitacoes', authMiddleware, async (req, res) => {
  try {
    const { id: usuarioId } = req.user;
    const {
      solicitante_nome,
      beneficiario_nome,
      beneficiario_doc,
      numero_nf,
      data_nf,
      valor_nf,
      emitente_nome,
      emitente_doc,
      status
    } = req.body;

    const result = await db.query(
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
        status
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      RETURNING *`,
      [
        usuarioId,
        solicitante_nome || null,
        beneficiario_nome || null,
        beneficiario_doc || null,
        numero_nf || null,
        data_nf || null,
        valor_nf || null,
        emitente_nome || null,
        emitente_doc || null,
        status || 'Em análise'
      ]
    );

    return res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro em POST /solicitacoes:', err);
    return res.status(500).json({ error: 'Erro ao criar solicitação.' });
  }
});

// Atualizar status (e outros campos simples)
app.put('/solicitacoes/:id', authMiddleware, async (req, res) => {
  try {
    const solId = parseInt(req.params.id, 10);
    const { id: usuarioId, tipo } = req.user;
    const { status } = req.body;

    // Garante que user comum só mexe nas suas
    let query = 'SELECT * FROM solicitacoes WHERE id = $1';
    let params = [solId];

    if (tipo !== 'admin') {
      query += ' AND usuario_id = $2';
      params.push(usuarioId);
    }

    const existing = await db.query(query, params);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Solicitação não encontrada.' });
    }

    const result = await db.query(
      `UPDATE solicitacoes
       SET status = COALESCE($1, status),
           data_ultima_mudanca = NOW()
       WHERE id = $2
       RETURNING *`,
      [status || null, solId]
    );

    return res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro em PUT /solicitacoes/:id:', err);
    return res.status(500).json({ error: 'Erro ao atualizar solicitação.' });
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
    console.error('Erro PATCH /descricoes:', err);
    res.status(500).json({ error: 'Erro ao atualizar descrição.' });
  }
});

app.delete('/descricoes/:id', authMiddleware, async (req, res) => {
  try {
    const id = req.params.id;

    await db.query(`DELETE FROM descricoes WHERE id = $1`, [id]);

    res.status(204).send();
  } catch (err) {
    console.error('Erro DELETE /descricoes:', err);
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
    console.error('Erro PATCH /status:', err);
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

// --------- Healthcheck ----------
app.get('/', (req, res) => {
  res.send('API Reembolso rodando.');
});

// --------- Start ----------
app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT}`);
});
