// index.js
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
app.post('/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) {
      return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
    }

    const result = await db.query(
      'SELECT id, nome, email, senha_hash, tipo, ativo FROM usuarios WHERE email = $1',
      [email]
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

    const payload = {
      id: user.id,
      nome: user.nome,
      email: user.email,
      tipo: user.tipo
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

    return res.json({ token, user: payload });
  } catch (err) {
    console.error('Erro em /auth/login:', err);
    return res.status(500).json({ error: 'Erro interno ao fazer login.' });
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

// ===================== USUÁRIOS ======================
app.get('/usuarios', authMiddleware, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, nome, email, tipo, ativo, telefone, cpfCnpj
       FROM usuarios
       ORDER BY id ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro em GET /usuarios:', err);
    res.status(500).json({ error: 'Erro ao listar usuários.' });
  }
});

app.post('/usuarios', authMiddleware, async (req, res) => {
  try {
    const { nome, email, telefone, cpf, cpfCnpj, tipo } = req.body;

    const result = await db.query(
      `INSERT INTO usuarios (nome, email, telefone, cpfCnpj, tipo, ativo)
       VALUES ($1,$2,$3,$4,$5,true)
       RETURNING id, nome, email, telefone, cpfCnpj, tipo, ativo`,
      [nome, email || null, telefone || null, cpfCnpj || cpf || null, tipo || 'user']
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro em POST /usuarios:', err);
    res.status(500).json({ error: 'Erro ao criar usuário.' });
  }
});

app.patch('/usuarios/:id', authMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    const { nome, email, telefone, cpfCnpj, tipo, ativo } = req.body;

    const result = await db.query(
      `UPDATE usuarios
       SET nome = COALESCE($1, nome),
           email = COALESCE($2, email),
           telefone = COALESCE($3, telefone),
           cpfCnpj = COALESCE($4, cpfCnpj),
           tipo = COALESCE($5, tipo),
           ativo = COALESCE($6, ativo)
       WHERE id = $7
       RETURNING id, nome, email, telefone, cpfCnpj, tipo, ativo`,
      [nome, email, telefone, cpfCnpj, tipo, ativo, id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro em PATCH /usuarios:', err);
    res.status(500).json({ error: 'Erro ao atualizar usuário.' });
  }
});

app.delete('/usuarios/:id', authMiddleware, async (req, res) => {
  try {
    const id = req.params.id;

    await db.query(`DELETE FROM usuarios WHERE id = $1`, [id]);

    res.status(204).send();
  } catch (err) {
    console.error('Erro em DELETE /usuarios:', err);
    res.status(500).json({ error: 'Erro ao excluir usuário.' });
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
    console.error('Erro DELETE /status:', err);
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
