// index.js — API Reembolso COMPLETA e ATUALIZADA 05/12/25
// Compatível com o schema/prisma atual e com o front (forma da resposta do login).

// =========================
// 🔰 IMPORTAÇÕES & SETUP
// =========================
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const prisma = new PrismaClient();

// Helper para acessar o modelo de anexos, qualquer que seja o nome no Prisma
const arquivosModel =
  prisma.solicitacao_arquivos ||      // ex: model Solicitacao_arquivos
  prisma.solicitacaoArquivos ||       // ex: model SolicitacaoArquivos
  prisma.arquivo ||                   // ex: model Arquivo
  prisma.arquivos ||                  // ex: model Arquivos
  null;

function getArquivosModel() {
  if (!arquivosModel) {
    console.error(
      "Modelo de anexos (solicitacao_arquivos / solicitacaoArquivos / arquivo) não encontrado no Prisma Client."
    );
  }
  return arquivosModel;
}

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
const APP_BASE_URL = process.env.APP_BASE_URL || "";

console.log("🔧 SMTP DEBUG:", {
  host: process.env.SMTP_HOST,
  user: process.env.SMTP_USER,
  hasPass: !!process.env.SMTP_PASS,
});

// =========================
// 🔰 MIDDLEWARES
// =========================
app.use(express.json());

// CORS dinâmico (Render + Vercel + localhost)
const allowedOrigins = ["http://localhost:5173", "http://localhost:3000"];

if (APP_BASE_URL) {
  allowedOrigins.push(APP_BASE_URL);
  if (!APP_BASE_URL.startsWith("http")) {
    allowedOrigins.push(`https://${APP_BASE_URL}`);
    allowedOrigins.push(`http://${APP_BASE_URL}`);
  }
}

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      if (origin.endsWith(".vercel.app") && origin.includes("controle-de-reembolso")) {
        return callback(null, true);
      }

      return callback(null, false);
    },
    credentials: true,
  })
);

// =========================
// 🔰 MIDDLEWARE — AUTENTICAÇÃO & PERFIL
// =========================
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ erro: "Token não enviado." });
  }

  const token = authHeader.replace("Bearer ", "").trim();

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const tipo = String(payload.tipo || "").toLowerCase();

    req.user = {
      id: payload.id,
      tipo,
    };
    next();
  } catch (err) {
    console.error("Erro ao verificar token:", err);
    return res.status(401).json({ erro: "Token inválido." });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.tipo !== "admin") {
    return res.status(403).json({ erro: "Acesso restrito a administradores." });
  }
  next();
}

// =========================
// 🔰 UPLOADS
// =========================
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination(req, file, cb) {
    cb(null, uploadDir);
  },
  filename(req, file, cb) {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, unique + ext);
  },
});

const upload = multer({ storage });

// =========================
// 🔰 HEALTH CHECK
// =========================
app.get("/health", async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Erro no /health:", err);
    res.status(500).json({ status: "error", message: "DB indisponível" });
  }
});

app.get("/", (req, res) => {
  res.send("API Reembolso rodando.");
});

// =========================
// 🔰 AUTH — LOGIN
// =========================
app.post("/auth/login", async (req, res) => {
  try {
    const { email, login, senha } = req.body;
    const identificador = email || login;

    if (!identificador || !senha) {
      return res.status(400).json({
        ok: false,
        success: false,
        status: "error",
        mensagem: "Usuário e senha são obrigatórios.",
      });
    }

    const usuario = await prisma.usuario.findFirst({
      where: {
        OR: [{ email: identificador }, { nome: identificador }],
      },
    });

    if (!usuario) {
      return res
        .status(400)
        .json({ ok: false, success: false, status: "error", mensagem: "Usuário não encontrado." });
    }

    const senhaOk = await bcrypt.compare(senha, usuario.senha_hash);
    if (!senhaOk) {
      return res
        .status(400)
        .json({ ok: false, success: false, status: "error", mensagem: "Usuário ou senha inválidos." });
    }

    if (!JWT_SECRET) {
      console.error("JWT_SECRET não definido");
      return res.status(500).json({
        ok: false,
        success: false,
        status: "error",
        mensagem: "Erro de configuração do servidor.",
      });
    }

    const token = jwt.sign(
      { id: usuario.id, tipo: (usuario.tipo || "").toLowerCase() },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    const userPayload = {
      id: usuario.id,
      nome: usuario.nome,
      email: usuario.email,
      cpfcnpj: usuario.cpfcnpj,
      telefone: usuario.telefone,
      tipo: usuario.tipo,
    };

    res.json({
      ok: true,
      success: true,
      status: "ok",
      message: "Login realizado com sucesso.",
      token,
      usuario: userPayload,
      user: userPayload,
      data: {
        token,
        usuario: userPayload,
        user: userPayload,
      },
    });
  } catch (err) {
    console.error("Erro em /auth/login:", err);
    res
      .status(500)
      .json({ ok: false, success: false, status: "error", mensagem: "Erro interno ao tentar fazer login." });
  }
});

// =========================
// 🔰 AUTH — RESET SENHA (SOLICITAR)
// =========================
app.post("/auth/reset-solicitar", async (req, res) => {
  try {
    const { email } = req.body;

    const usuario = await prisma.usuario.findFirst({
      where: { email },
    });
    if (!usuario) {
      return res.status(400).json({ erro: "Usuário não encontrado." });
    }

    const token = Math.random().toString(36).substring(2, 15);
    const expires = new Date(Date.now() + 60 * 60 * 1000);

    await prisma.usuario.update({
      where: { id: usuario.id },
      data: {
        reset_token: token,
        reset_token_expires: expires,
      },
    });

    const base = APP_BASE_URL.replace(/\/$/, "");
    const resetLink = `${base}/resetar-senha/${token}`;

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT),
      secure: process.env.SMTP_SECURE === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    await transporter.sendMail({
      from: process.env.MAIL_FROM,
      to: usuario.email,
      subject: "Redefinição de senha - Controle de Reembolso",
      html: `
        <p>Olá, ${usuario.nome}</p>
        <p>Clique no link abaixo para redefinir sua senha:</p>
        <p><a href="${resetLink}">${resetLink}</a></p>
      `,
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erro em /auth/reset-solicitar:", err);
    res.status(500).json({ erro: "Erro ao solicitar redefinição de senha." });
  }
});

// Alias compatível com o front
app.post("/auth/esqueci-senha", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ ok: false, mensagem: "E-mail é obrigatório." });
    }

    const usuario = await prisma.usuario.findFirst({
      where: { email },
    });

    if (!usuario) {
      return res.json({
        ok: true,
        emailEnviado: false,
      });
    }

    const token = Math.random().toString(36).substring(2, 15);

    await prisma.usuario.update({
      where: { id: usuario.id },
      data: {
        reset_token: token,
      },
    });

    const base = (APP_BASE_URL || "").replace(/\/$/, "");
    const resetLink = `${
      base || "https://controle-de-reembolso.vercel.app"
    }/resetar-senha/${token}`;

    let emailEnviado = false;

    if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
      try {
        const transporter = nodemailer.createTransport({
          host: process.env.SMTP_HOST,
          port: Number(process.env.SMTP_PORT) || 587,
          secure: process.env.SMTP_SECURE === "true",
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
          },
          connectionTimeout: 5000,
          greetingTimeout: 5000,
          socketTimeout: 5000,
        });

        await transporter.sendMail({
          from: process.env.MAIL_FROM || process.env.SMTP_USER,
          to: usuario.email,
          subject: "Redefinição de senha - Controle de Reembolso",
          html: `
            <p>Olá, ${usuario.nome}</p>
            <p>Clique no link abaixo para redefinir sua senha:</p>
            <p><a href="${resetLink}">${resetLink}</a></p>
          `,
        });

        emailEnviado = true;
      } catch (errMail) {
        console.error("⚠ Erro ao enviar e-mail de redefinição:", errMail);
        console.log("🔗 Link de redefinição gerado:", resetLink);
      }
    } else {
      console.warn(
        "⚠ SMTP não configurado. E-mail de reset NÃO enviado (HOST/USER/PASS ausentes)."
      );
      console.log("🔗 Link de redefinição gerado:", resetLink);
    }

    return res.json({ ok: true, emailEnviado });
  } catch (err) {
    console.error("Erro em /auth/esqueci-senha:", err);
    return res.status(200).json({
      ok: false,
      emailEnviado: false,
      mensagem: "Erro ao solicitar redefinição de senha.",
    });
  }
});

// =========================
// 🔰 AUTH — RESET SENHA (CONFIRMAR)
// =========================
app.post("/auth/reset-confirmar", async (req, res) => {
  try {
    const { token, novaSenha } = req.body;

    if (!token || !novaSenha) {
      return res.status(400).json({ erro: "Token e nova senha são obrigatórios." });
    }

    const usuario = await prisma.usuario.findFirst({
      where: {
        reset_token: token,
      },
    });

    if (!usuario) {
      return res.status(400).json({ erro: "Token inválido." });
    }

    const hash = await bcrypt.hash(novaSenha, 10);

    await prisma.usuario.update({
      where: { id: usuario.id },
      data: {
        senha_hash: hash,
        reset_token: null,
      },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erro em /auth/reset-confirmar:", err);
    res.status(500).json({ erro: "Erro ao redefinir senha." });
  }
});

// =========================
// 🔰 USUÁRIOS
// =========================
app.get("/usuarios/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const usuario = await prisma.usuario.findUnique({
      where: { id: Number(id) },
    });

    if (!usuario) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    res.json(usuario);
  } catch (err) {
    console.error("Erro em GET /usuarios/:id:", err);
    res.status(500).json({ erro: "Erro ao buscar usuário." });
  }
});

app.get("/usuarios", async (req, res) => {
  try {
    const usuarios = await prisma.usuario.findMany({
      orderBy: { nome: "asc" },
    });

    res.json(usuarios);
  } catch (err) {
    console.error("Erro em GET /usuarios:", err);
    res.status(500).json({ erro: "Erro ao listar usuários." });
  }
});

// Helper p/ mapear solicitante e anexos
function mapSolicitacaoComSolicitante(s) {
  const nomeSolicitante = s.usuario?.nome || s.solicitante_nome || s.solicitante || "";

  const arquivosArray = s.arquivos || s.solicitacao_arquivos || [];

  const count = arquivosArray.length;

  return {
    ...s,
    solicitante_nome: nomeSolicitante,
    solicitante: nomeSolicitante,
    solicitacao_arquivos: arquivosArray,
    arquivos: arquivosArray,
    documentos: arquivosArray,

    docs: count,
    docs_count: count,
    documentos_count: count,
    qtd_arquivos: count,
    qtd_documentos: count,
  };
}

// =========================
// 🔰 USUÁRIOS — CRUD (Configurações)
// =========================
app.post("/usuarios", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { nome, email, senha, tipo, ativo, cpfcnpj, telefone } = req.body;

    if (!nome || !email || !senha) {
      return res
        .status(400)
        .json({ erro: "Nome, e-mail e senha são obrigatórios." });
    }

    const existente = await prisma.usuario.findFirst({ where: { email } });

    if (existente) {
      return res
        .status(400)
        .json({ erro: "Já existe um usuário cadastrado com esse e-mail." });
    }

    const hash = await bcrypt.hash(senha, 10);

    const novo = await prisma.usuario.create({
      data: {
        nome: String(nome).trim(),
        email: String(email).trim(),
        senha_hash: hash,
        tipo: tipo || "user",
        ativo: ativo !== undefined ? !!ativo : true,
        cpfcnpj: cpfcnpj || null,
        telefone: telefone || null,
        primeiro_acesso: true,
      },
    });

    res.json(novo);
  } catch (err) {
    console.error("Erro em POST /usuarios:", err);
    res.status(500).json({ erro: "Erro ao salvar usuário." });
  }
});

app.put("/usuarios/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { nome, email, senha, tipo, ativo, cpfcnpj, telefone } = req.body;

    const data = {};

    if (nome !== undefined) data.nome = String(nome).trim();
    if (email !== undefined) data.email = String(email).trim();
    if (tipo !== undefined) data.tipo = tipo;
    if (ativo !== undefined) data.ativo = !!ativo;
    if (cpfcnpj !== undefined) data.cpfcnpj = cpfcnpj || null;
    if (telefone !== undefined) data.telefone = telefone || null;

    if (senha) {
      data.senha_hash = await bcrypt.hash(senha, 10);
      data.primeiro_acesso = false;
    }

    const atualizado = await prisma.usuario.update({
      where: { id: Number(id) },
      data,
    });

    res.json(atualizado);
  } catch (err) {
    console.error("Erro em PUT /usuarios/:id:", err);
    res.status(500).json({ erro: "Erro ao salvar usuário." });
  }
});

app.delete("/usuarios/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;

    if (req.user && req.user.id === Number(id)) {
      return res
        .status(400)
        .json({ erro: "Você não pode excluir o próprio usuário logado." });
    }

    await prisma.usuario.delete({
      where: { id: Number(id) },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erro em DELETE /usuarios/:id:", err);
    res.status(500).json({ erro: "Erro ao excluir usuário." });
  }
});

// =========================
// 🔰 DESCRIÇÕES DE DESPESAS
// =========================
app.get("/descricoes", async (req, res) => {
  try {
    const descricoes = await prisma.$queryRaw`
      SELECT id, descricao, ativo
      FROM descricoes
      WHERE ativo = true
      ORDER BY descricao;
    `;
    res.json(descricoes);
  } catch (err) {
    console.error("Erro em GET /descricoes:", err);
    res.status(500).json({ erro: "Erro ao listar descrições." });
  }
});

app.post("/descricoes", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { descricao, ativo } = req.body;

    if (!descricao || !String(descricao).trim()) {
      return res
        .status(400)
        .json({ erro: "Descrição da despesa é obrigatória." });
    }

    const [novo] = await prisma.$queryRaw`
      INSERT INTO descricoes (descricao, ativo)
      VALUES (${String(descricao).trim()}, ${ativo !== undefined ? !!ativo : true})
      RETURNING id, descricao, ativo;
    `;

    res.json(novo);
  } catch (err) {
    console.error("Erro em POST /descricoes:", err);
    res.status(500).json({ erro: "Erro ao salvar descrição." });
  }
});

app.put("/descricoes/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { descricao, ativo } = req.body;

    const [atualizado] = await prisma.$queryRaw`
      UPDATE descricoes
      SET
        descricao = COALESCE(${descricao !== undefined ? String(descricao).trim() : null}, descricao),
        ativo = COALESCE(${ativo !== undefined ? !!ativo : null}, ativo)
      WHERE id = ${Number(id)}
      RETURNING id, descricao, ativo;
    `;

    if (!atualizado) {
      return res.status(404).json({ erro: "Descrição não encontrada." });
    }

    res.json(atualizado);
  } catch (err) {
    console.error("Erro em PUT /descricoes/:id:", err);
    res.status(500).json({ erro: "Erro ao atualizar descrição." });
  }
});

app.delete("/descricoes/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.$executeRaw`
      DELETE FROM descricoes WHERE id = ${Number(id)};
    `;

    res.json({ ok: true });
  } catch (err) {
    console.error("Erro em DELETE /descricoes/:id:", err);
    res.status(500).json({ erro: "Erro ao excluir descrição." });
  }
});

// =========================
// 🔰 STATUS
// =========================
app.post("/status", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { nome, descricao, ativo } = req.body;

    if (!nome || !String(nome).trim()) {
      return res.status(400).json({ erro: "Nome do status é obrigatório." });
    }

    const novo = await prisma.status.create({
      data: {
        nome: String(nome).trim(),
        descricao: descricao || null,
        ativo: ativo !== undefined ? !!ativo : true,
      },
    });

    res.json(novo);
  } catch (err) {
    console.error("Erro em POST /status:", err);
    res.status(500).json({ erro: "Erro ao salvar status." });
  }
});

app.get("/status", authMiddleware, async (req, res) => {
  try {
    const lista = await prisma.status.findMany({
      orderBy: { id: "asc" },
    });
    res.json(lista);
  } catch (err) {
    console.error("Erro em GET /status:", err);
    res.status(500).json({ erro: "Erro ao listar status." });
  }
});

app.put("/status/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { nome, descricao, ativo } = req.body;

    const data = {};
    if (nome !== undefined) data.nome = String(nome).trim();
    if (descricao !== undefined) data.descricao = descricao || null;
    if (ativo !== undefined) data.ativo = !!ativo;

    const atualizado = await prisma.status.update({
      where: { id: Number(id) },
      data,
    });

    res.json(atualizado);
  } catch (err) {
    console.error("Erro em PUT /status/:id:", err);
    res.status(500).json({ erro: "Erro ao atualizar status." });
  }
});

// =========================
// 🔰 SOLICITAÇÕES — LISTAR
// =========================
app.get("/solicitacoes/usuario/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const usuarioId = Number(id);

    if (req.user.tipo !== "admin" && req.user.id !== usuarioId) {
      return res.status(403).json({ erro: "Acesso negado para este usuário." });
    }

    const dados = await prisma.solicitacao.findMany({
      where: { usuario_id: usuarioId },
      orderBy: { criado_em: "desc" },
      include: {
        arquivos: true,
        usuario: true,
      },
    });

    const resposta = dados.map(mapSolicitacaoComSolicitante);

    res.json(resposta);
  } catch (err) {
    console.error("Erro em GET /solicitacoes/usuario/:id:", err);
    res.status(500).json({ erro: "Erro ao buscar solicitações." });
  }
});

app.get("/solicitacoes", authMiddleware, adminOnly, async (req, res) => {
  try {
    const registros = await prisma.solicitacao.findMany({
      orderBy: { criado_em: "desc" },
      include: {
        arquivos: true,
        usuario: true,
      },
    });

    const resposta = registros.map(mapSolicitacaoComSolicitante);

    res.json(resposta);
  } catch (err) {
    console.error("Erro em GET /solicitacoes:", err);
    res.status(500).json({ erro: "Erro ao listar solicitações." });
  }
});

// =========================
// 🔰 HELPERS — NÚMEROS E DATAS
// =========================
function normalizarNumero(valor) {
  if (valor === null || valor === undefined || valor === "") return null;
  if (typeof valor === "number") return valor;
  const limpo = String(valor).replace(/\./g, "").replace(",", ".");
  const num = Number(limpo);
  return Number.isNaN(num) ? null : num;
}

const camposPermitidos = [
  "usuario_id",
  "solicitante_nome",
  "beneficiario_nome",
  "beneficiario_doc",
  "numero_nf",
  "data_nf",
  "valor_nf",
  "emitente_nome",
  "emitente_doc",
  "status",
  "data_solicitacao",
  "data_ultima_mudanca",
  "protocolo",
  "valor",
  "descricao",
  "data_pagamento",
  "valor_reembolso",
];

const camposNumericos = ["valor_nf", "valor", "valor_reembolso"];

const camposData = ["data_nf", "data_solicitacao", "data_ultima_mudanca", "data_pagamento"];

function normalizarData(valor) {
  if (valor === null || valor === undefined || valor === "") return null;
  if (valor instanceof Date) return valor;

  const s = String(valor).trim();

  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
    const d = new Date(s + "T00:00:00.000Z");
    if (isNaN(d.getTime())) return null;
    return d;
  }

  const d = new Date(s);
  if (isNaN(d.getTime())) return null;
  return d;
}

// =========================
// 🔰 SOLICITAÇÕES — CRIAR / ATUALIZAR
// =========================
app.post("/solicitacoes", authMiddleware, async (req, res) => {
  try {
    const dados = req.body;

    let usuarioIdSolicitante = Number(dados.usuario_id || req.user.id);
    if (Number.isNaN(usuarioIdSolicitante) || usuarioIdSolicitante <= 0) {
      usuarioIdSolicitante = req.user.id;
    }

    if (req.user.tipo !== "admin" && req.user.id !== usuarioIdSolicitante) {
      return res.status(403).json({
        erro: "Usuário não autorizado a criar solicitação para outro solicitante.",
      });
    }

    const dataCriar = {
      usuario_id: usuarioIdSolicitante,
    };

    for (const campo of camposPermitidos) {
      if (!Object.prototype.hasOwnProperty.call(dados, campo)) continue;
      let valor = dados[campo];

      if (valor === undefined || valor === "") continue;
      if (campo === "usuario_id") continue;

      if (camposNumericos.includes(campo)) {
        const num = normalizarNumero(valor);
        if (num === null) continue;
        dataCriar[campo] = num;
        continue;
      }

      if (camposData.includes(campo)) {
        const dt = normalizarData(valor);
        if (!dt) continue;
        dataCriar[campo] = dt;
        continue;
      }

      dataCriar[campo] = valor;
    }

    if (!dataCriar.status) {
      dataCriar.status = dados.status || "Em análise";
    }

    const nova = await prisma.solicitacao.create({
      data: dataCriar,
    });

    res.json(nova);
  } catch (err) {
    console.error("Erro em POST /solicitacoes:", err);
    res.status(500).json({ erro: "Erro ao criar solicitação." });
  }
});

app.put("/solicitacoes/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const dados = req.body;
    const solicitacaoId = Number(id);

    const existente = await prisma.solicitacao.findUnique({
      where: { id: solicitacaoId },
    });

    if (!existente) {
      return res.status(404).json({ erro: "Solicitação não encontrada." });
    }

    if (req.user.tipo !== "admin" && existente.usuario_id !== req.user.id) {
      return res.status(403).json({
        erro: "Usuário não autorizado a alterar esta solicitação.",
      });
    }

    const dataAtualizar = {};

    for (const campo of camposPermitidos) {
      if (!Object.prototype.hasOwnProperty.call(dados, campo)) continue;

      let valor = dados[campo];

      if (valor === undefined) continue;

      if (campo === "usuario_id") {
        const idNum = Number(valor);
        if (!Number.isNaN(idNum) && idNum > 0) {
          dataAtualizar.usuario_id = idNum;
        }
        continue;
      }

      if (camposNumericos.includes(campo)) {
        const num = normalizarNumero(valor);
        if (num === null) continue;
        dataAtualizar[campo] = num;
        continue;
      }

      if (camposData.includes(campo)) {
        const dt = normalizarData(valor);
        if (!dt) continue;
        dataAtualizar[campo] = dt;
        continue;
      }

      dataAtualizar[campo] = valor;
    }

    if (Object.prototype.hasOwnProperty.call(dataAtualizar, "status")) {
      dataAtualizar.data_ultima_mudanca = new Date();
    }

    if (Object.keys(dataAtualizar).length === 0) {
      return res.json(existente);
    }

    const atualizado = await prisma.solicitacao.update({
      where: { id: solicitacaoId },
      data: dataAtualizar,
    });

    res.json(atualizado);
  } catch (err) {
    console.error("Erro em PUT /solicitacoes/:id:", err);
    res.status(500).json({ erro: "Erro ao atualizar solicitação." });
  }
});

// =========================
// 🔰 SOLICITAÇÕES — DELETE
// =========================
app.delete("/solicitacoes/:id", authMiddleware, async (req, res) => {
  try {
    const solicitacaoId = Number(req.params.id);

    const solicitacao = await prisma.solicitacao.findUnique({
      where: { id: solicitacaoId },
      include: { arquivos: true },
    });

    if (!solicitacao) {
      return res.status(404).json({ erro: "Solicitação não encontrada." });
    }

    // Regras:
    // - Admin pode excluir qualquer solicitação
    // - Usuário só pode excluir as próprias
    if (req.user.tipo !== "admin" && solicitacao.usuario_id !== req.user.id) {
      return res.status(403).json({
        erro: "Usuário não autorizado a excluir esta solicitação.",
      });
    }

    const arquivos = solicitacao.arquivos || [];
    for (const arq of arquivos) {
      if (!arq.path) continue;
      const fullPath = path.join(uploadDir, arq.path);
      try {
        if (fs.existsSync(fullPath)) {
          fs.unlinkSync(fullPath);
        }
      } catch (e) {
        console.error(
          `Erro ao remover arquivo físico (id=${arq.id}, path=${arq.path}):`,
          e
        );
      }
    }

    // Deleta registros de arquivos, se o modelo existir
    if (prisma.solicitacao_arquivos?.deleteMany) {
      try {
        await prisma.solicitacao_arquivos.deleteMany({
          where: { solicitacao_id: solicitacaoId },
        });
      } catch (e) {
        console.error(
          "Erro ao apagar registros de arquivos (ignorando e prosseguindo):",
          e
        );
      }
    }

    // Remove histórico de status (se o modelo existir)
    if (prisma.solicitacao_status_history?.deleteMany) {
      try {
        await prisma.solicitacao_status_history.deleteMany({
          where: { solicitacao_id: solicitacaoId },
        });
      } catch (e) {
        console.error(
          "Erro ao apagar histórico de status da solicitação (ignorando e prosseguindo):",
          e
        );
      }
    } else {
      console.warn(
        "Modelo solicitacao_status_history não existe no Prisma – pulando exclusão de histórico."
      );
    }

    await prisma.solicitacao.delete({
      where: { id: solicitacaoId },
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("Erro em DELETE /solicitacoes/:id:", err);
    res.status(500).json({ erro: "Erro ao excluir solicitação." });
  }
});

// =========================
// 🔰 UPLOAD DE ARQUIVOS
// =========================
app.post(
  "/solicitacoes/:id/arquivos",
  authMiddleware,
  upload.single("file"), // ou "arquivo", conforme está no frontend
  async (req, res) => {
    try {
      const solicitacaoId = Number(req.params.id);
      const { tipo } = req.body;
      const file = req.file;

      if (!file) {
        return res.status(400).json({ erro: "Nenhum arquivo enviado." });
      }

      const solicitacao = await prisma.solicitacao.findUnique({
        where: { id: solicitacaoId },
      });

      if (!solicitacao) {
        return res.status(404).json({ erro: "Solicitação não encontrada." });
      }

      // Segurança: admin pode tudo, usuário só na própria solicitação
      if (req.user.tipo !== "admin" && solicitacao.usuario_id !== req.user.id) {
        return res.status(403).json({
          erro: "Usuário não autorizado a anexar arquivos nesta solicitação.",
        });
      }

      const Arquivos = getArquivosModel();
      if (!Arquivos) {
        return res
          .status(500)
          .json({ erro: "Modelo de anexos não configurado na API." });
      }

      // 🔁 Tenta com todos os campos; se der erro de schema, tenta com o mínimo
      let registro;
      try {
        registro = await Arquivos.create({
          data: {
            solicitacao_id: solicitacaoId,
            tipo: tipo || "outro",
            original_name: file.originalname,
            mime_type: file.mimetype,
            path: file.filename,
          },
        });
      } catch (errPrisma) {
        console.error(
          "Falha ao criar registro de anexo com todos os campos, tentando apenas campos mínimos:",
          errPrisma
        );
        registro = await Arquivos.create({
          data: {
            solicitacao_id: solicitacaoId,
            original_name: file.originalname,
            path: file.filename,
          },
        });
      }

      res.json(registro);
    } catch (err) {
      console.error("Erro em POST /solicitacoes/:id/arquivos:", err);
      res.status(500).json({
        erro: "Erro ao enviar arquivo.",
        detalhe: err?.message || String(err),
      });
    }
  }
);

// =========================
// 🔰 LISTAR ARQUIVOS
// =========================
app.get("/solicitacoes/:id/arquivos", authMiddleware, async (req, res) => {
  try {
    const solicitacaoId = Number(req.params.id);

    const solicitacao = await prisma.solicitacao.findUnique({
      where: { id: solicitacaoId },
    });

    if (!solicitacao) {
      return res.status(404).json({ erro: "Solicitação não encontrada." });
    }

    if (req.user.tipo !== "admin" && solicitacao.usuario_id !== req.user.id) {
      return res.status(403).json({
        erro: "Usuário não autorizado a visualizar arquivos desta solicitação.",
      });
    }

    const Arquivos = getArquivosModel();
    if (!Arquivos) {
      return res
        .status(500)
        .json({ erro: "Modelo de anexos não configurado na API." });
    }

    const arquivos = await Arquivos.findMany({
      where: { solicitacao_id: solicitacaoId },
      orderBy: { created_at: "desc" },
    });

    res.json(arquivos);
  } catch (err) {
    console.error("Erro em GET /solicitacoes/:id/arquivos:", err);
    res.status(500).json({ erro: "Erro ao listar arquivos." });
  }
});

// =========================
// 🔰 DOWNLOAD ARQUIVO
// =========================
app.get("/arquivos/:id/download", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const Arquivos = getArquivosModel();
    if (!Arquivos) {
      return res
        .status(500)
        .json({ erro: "Modelo de anexos não configurado na API." });
    }

    const arquivo = await Arquivos.findUnique({
      where: { id: Number(id) },
    });

    if (!arquivo) {
      return res.status(404).json({ erro: "Arquivo não encontrado." });
    }

    const solicitacao = await prisma.solicitacao.findUnique({
      where: { id: arquivo.solicitacao_id },
    });

    if (!solicitacao) {
      return res.status(404).json({ erro: "Solicitação não encontrada." });
    }

    if (req.user.tipo !== "admin" && solicitacao.usuario_id !== req.user.id) {
      return res.status(403).json({
        erro: "Usuário não autorizado a baixar este arquivo.",
      });
    }

    const fullPath = path.join(uploadDir, arquivo.path);

    if (!fs.existsSync(fullPath)) {
      return res
        .status(410)
        .json({ erro: "Arquivo não está mais disponível." });
    }

    res.download(fullPath, arquivo.original_name);
  } catch (err) {
    console.error("Erro em GET /arquivos/:id/download:", err);
    res.status(500).json({ erro: "Erro ao fazer download do arquivo." });
  }
});

// =========================
// 🔰 REMOVER ARQUIVO
// =========================
app.delete("/arquivos/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const arquivo = await prisma.solicitacao_arquivos.findUnique({
      where: { id: Number(id) },
    });

    if (!arquivo) {
      return res.status(404).json({ erro: "Arquivo não encontrado." });
    }

    const solicitacao = await prisma.solicitacao.findUnique({
      where: { id: arquivo.solicitacao_id },
    });

    if (!solicitacao) {
      return res.status(404).json({ erro: "Solicitação não encontrada." });
    }

    if (req.user.tipo !== "admin" && solicitacao.usuario_id !== req.user.id) {
      return res.status(403).json({
        erro: "Usuário não autorizado a remover este arquivo.",
      });
    }

    const fullPath = path.join(uploadDir, arquivo.path);

    if (fs.existsSync(fullPath)) {
      fs.unlinkSync(fullPath);
    }

    await prisma.solicitacao_arquivos.delete({
      where: { id: Number(id) },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erro em DELETE /arquivos/:id:", err);
    res.status(500).json({ erro: "Erro ao remover arquivo." });
  }
});

// =========================
// 🔰 HISTÓRICO DE STATUS (por solicitação / global)
// =========================
app.get("/solicitacoes/:id/historico", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const solicitacaoId = Number(id);

    const solicitacao = await prisma.solicitacao.findUnique({
      where: { id: solicitacaoId },
    });

    if (!solicitacao) {
      return res.status(404).json({ erro: "Solicitação não encontrada." });
    }

    if (req.user.tipo !== "admin" && solicitacao.usuario_id !== req.user.id) {
      return res.status(403).json({
        erro: "Usuário não autorizado a ver histórico desta solicitação.",
      });
    }

    if (!prisma.solicitacao_status_history?.findMany) {
      console.warn(
        "Modelo solicitacao_status_history não existe; retornando histórico vazio."
      );
      return res.json([]);
    }

    const lista = await prisma.solicitacao_status_history.findMany({
      where: { solicitacao_id: solicitacaoId },
      orderBy: { data: "desc" },
    });

    res.json(lista);
  } catch (err) {
    console.error("Erro em GET /solicitacoes/:id/historico:", err);
    res.status(500).json({ erro: "Erro ao buscar histórico." });
  }
});

// =========================
// 🔰 ATUALIZAR STATUS DA SOLICITAÇÃO (com histórico) — ADMIN
// =========================
app.put("/solicitacoes/:id/status", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, origem, obs } = req.body;

    const statusList = await prisma.status.findMany({
      where: { ativo: true },
      orderBy: { id: "asc" },
    });

    const nomesStatus = statusList.map((s) => s.nome);
    if (!nomesStatus.includes(status)) {
      return res.status(400).json({
        erro: "Status inválido. Use um dos disponíveis na tabela 'status'.",
        permitidos: nomesStatus,
      });
    }

    const atualizado = await prisma.solicitacao.update({
      where: { id: Number(id) },
      data: {
        status,
        data_ultima_mudanca: new Date(),
      },
    });

    if (prisma.solicitacao_status_history?.create) {
      await prisma.solicitacao_status_history.create({
        data: {
          solicitacao_id: Number(id),
          status,
          data: new Date(),
          origem: origem || "Sistema",
          obs: obs || null,
        },
      });
    } else {
      console.warn(
        "Modelo solicitacao_status_history não existe; não será gravado histórico."
      );
    }

    res.json({ ok: true, atualizado });
  } catch (err) {
    console.error("Erro em PUT /solicitacoes/:id/status:", err);
    res.status(500).json({ erro: "Erro ao atualizar status." });
  }
});

// =========================
// 🔰 KANBAN
// =========================
app.get("/kanban", authMiddleware, adminOnly, async (req, res) => {
  try {
    const statusList = await prisma.status.findMany({
      where: { ativo: true },
      orderBy: { id: "asc" },
    });

    const solicitacoes = await prisma.solicitacao.findMany({
      orderBy: { criado_em: "desc" },
      include: {
        arquivos: true,
        usuario: true,
      },
    });

    const grupos = {};
    statusList.forEach((s) => {
      grupos[s.nome] = [];
    });

    solicitacoes
      .map(mapSolicitacaoComSolicitante)
      .forEach((s) => {
        if (!grupos[s.status]) grupos[s.status] = [];
        grupos[s.status].push(s);
      });

    res.json(grupos);
  } catch (err) {
    console.error("Erro em GET /kanban:", err);
    res.status(500).json({ erro: "Erro ao buscar dados do Kanban." });
  }
});

// =========================
// 🔰 DASHBOARD
// =========================
app.get("/dashboard", authMiddleware, adminOnly, async (req, res) => {
  try {
    const totalSolicitacoes = await prisma.solicitacao.count();

    const totaisPorStatusRaw = await prisma.solicitacao.groupBy({
      by: ["status"],
      _count: { status: true },
    });

    const totaisPorStatus = {};
    totaisPorStatusRaw.forEach((item) => {
      totaisPorStatus[item.status] = item._count.status;
    });

    const ultimasRaw = await prisma.solicitacao.findMany({
      orderBy: { criado_em: "desc" },
      take: 10,
      include: {
        arquivos: true,
        usuario: true,
      },
    });

    const ultimas = ultimasRaw.map(mapSolicitacaoComSolicitante);

    res.json({
      totalSolicitacoes,
      totaisPorStatus,
      ultimas,
    });
  } catch (err) {
    console.error("Erro em GET /dashboard:", err);
    res.status(500).json({ erro: "Erro ao montar dashboard." });
  }
});

// =========================
// 🔰 HISTÓRICO GLOBAL
// =========================
app.get("/historico", authMiddleware, adminOnly, async (req, res) => {
  try {
    if (!prisma.solicitacao_status_history?.findMany) {
      console.warn(
        "Modelo solicitacao_status_history não existe; retornando histórico vazio."
      );
      return res.json([]);
    }

    const lista = await prisma.solicitacao_status_history.findMany({
      orderBy: { data: "desc" },
    });

    res.json(lista);
  } catch (err) {
    console.error("Erro em GET /historico:", err);
    res.status(500).json({ erro: "Erro ao buscar histórico global." });
  }
});

// =========================
// 🔰 RELATÓRIO IRPF
// =========================
app.get("/relatorios/irpf", authMiddleware, adminOnly, async (req, res) => {
  try {
    const dados = await prisma.solicitacao.findMany({
      orderBy: { criado_em: "desc" },
      include: {
        arquivos: true,
      },
    });

    const resultado = dados.map((s) => ({
      id: s.id,
      solicitante_id: s.usuario_id,
      beneficiario_nome: s.beneficiario_nome,
      beneficiario_doc: s.beneficiario_doc,
      numero_nf: s.numero_nf,
      data_nf: s.data_nf,
      valor_nf: s.valor_nf,
      emitente_nome: s.emitente_nome,
      emitente_doc: s.emitente_doc,
      status: s.status,
      data_pagamento: s.data_pagamento,
      valor_reembolso: s.valor_reembolso,
      criado_em: s.criado_em,
    }));

    res.json(resultado);
  } catch (err) {
    console.error("Erro em GET /relatorios/irpf:", err);
    res.status(500).json({ erro: "Erro ao gerar relatório." });
  }
});

// =========================
// 🔰 ESTRUTURA DO BANCO (TXT)
// =========================
app.get("/config/estrutura-banco", authMiddleware, adminOnly, async (req, res) => {
  try {
    const result = await prisma.$queryRawUnsafe(`
      SELECT table_name, column_name, data_type, is_nullable
      FROM information_schema.columns
      WHERE table_schema = 'public'
      ORDER BY table_name, ordinal_position;
    `);

    let txt = "Controle de Reembolso – Estrutura do Banco de Dados\n";
    txt += `Gerado em: ${new Date().toLocaleString()}\n\n`;

    let tabelaAtual = null;

    for (const row of result) {
      if (tabelaAtual !== row.table_name) {
        tabelaAtual = row.table_name;
        txt += `TABELA ${tabelaAtual}\n`;
      }
      txt += `- ${row.column_name} ${row.data_type} ${
        row.is_nullable === "NO" ? "NOT NULL" : ""
      }\n`;
    }

    const filePath = path.join(__dirname, "estrutura_banco.txt");
    fs.writeFileSync(filePath, txt);

    res.download(filePath, "estrutura_banco.txt");
  } catch (err) {
    console.error("Erro em /config/estrutura-banco:", err);
    res.status(500).json({ erro: "Erro ao gerar estrutura do banco." });
  }
});

// =========================
// 🔰 MIDDLEWARE DE ERRO GLOBAL
// =========================
app.use((err, req, res, next) => {
  console.error("Erro interno não tratado:", err);
  res.status(500).json({ error: "Erro interno do servidor" });
});

// =========================
// 🔰 INICIAR SERVIDOR
// =========================
app.listen(PORT, () => {
  console.log(`🚀 API Reembolso rodando na porta ${PORT}`);
});
