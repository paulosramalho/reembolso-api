// index.js — API Reembolso COMPLETA e ATUALIZADA 03/12/25 - 15:21h
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

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
const APP_BASE_URL = process.env.APP_BASE_URL || "";

// =========================
// 🔰 MIDDLEWARES
// =========================
app.use(express.json());

// CORS dinâmico (Render + Vercel + localhost)
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
];

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
      tipo: usuario.tipo, // mantém como está no banco pra UI
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

    const usuario = await prisma.usuario.findUnique({ where: { email } });
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

    const usuario = await prisma.usuario.findUnique({ where: { email } });
    if (!usuario) {
      return res
        .status(400)
        .json({ ok: false, mensagem: "Usuário não encontrado." });
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
    console.error("Erro em /auth/esqueci-senha:", err);
    res
      .status(500)
      .json({ ok: false, mensagem: "Erro ao solicitar redefinição de senha." });
  }
});

// =========================
// 🔰 AUTH — RESET SENHA (CONFIRMAR)
// =========================
app.post("/auth/reset-confirmar", async (req, res) => {
  try {
    const { token, novaSenha } = req.body;

    const usuario = await prisma.usuario.findFirst({
      where: {
        reset_token: token,
        reset_token_expires: { gte: new Date() },
      },
    });

    if (!usuario) {
      return res.status(400).json({ erro: "Token inválido ou expirado." });
    }

    const hash = await bcrypt.hash(novaSenha, 10);

    await prisma.usuario.update({
      where: { id: usuario.id },
      data: {
        senha_hash: hash,
        reset_token: null,
        reset_token_expires: null,
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

// Obter usuário por ID
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

// Listar usuários
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

// =========================
// 🔰 STATUS
// =========================
app.get("/status", async (req, res) => {
  try {
    const lista = await prisma.$queryRaw`
      SELECT id, nome, descricao, ativo
      FROM status
      WHERE ativo = true
      ORDER BY id;
    `;

    res.json(lista);
  } catch (err) {
    console.error("Erro em GET /status:", err);
    res.status(500).json({ erro: "Erro ao listar status." });
  }
});

// =========================
// 🔰 SOLICITAÇÕES — LISTAR POR USUÁRIO (Solicitante real)
// =========================
app.get("/solicitacoes/usuario/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const usuarioId = Number(id);

    // Se não for admin, só pode ver as próprias
    if (req.user.tipo !== "admin" && req.user.id !== usuarioId) {
      return res.status(403).json({ erro: "Acesso negado para este usuário." });
    }

    const dados = await prisma.solicitacao.findMany({
  where: { usuario_id: usuarioId },
  orderBy: { criado_em: "desc" },
  include: {
    arquivos: true,       // ✅ relação com a tabela de arquivos
    statusHistory: true,  // ✅ histórico de status
    usuario: true,        // ✅ dados do solicitante
  },
});

    res.json(dados);
  } catch (err) {
    console.error("Erro em GET /solicitacoes/usuario/:id:", err);
    res.status(500).json({ erro: "Erro ao buscar solicitações." });
  }
});

// =========================
// 🔰 SOLICITAÇÕES — LISTA GERAL (ADMIN)
// =========================
app.get("/solicitacoes", authMiddleware, adminOnly, async (req, res) => {
  try {
    const registros = await prisma.solicitacao.findMany({
  orderBy: { criado_em: "desc" },
  include: {
    arquivos: true,       // ✅
    statusHistory: true,  // ✅
    usuario: true,        // ✅
  },
});

    // Juntar dados do solicitante
    const usuarios = await prisma.usuario.findMany();
    const mapaUsuarios = new Map();
    usuarios.forEach((u) => mapaUsuarios.set(u.id, u));

    const resposta = registros.map((r) => ({
      ...r,
      solicitante: mapaUsuarios.get(r.usuario_id) || null,
    }));

    res.json(resposta);
  } catch (err) {
    console.error("Erro em GET /solicitacoes:", err);
    res.status(500).json({ erro: "Erro ao listar solicitações." });
  }
});

// =========================
// 🔰 CRIAR SOLICITAÇÃO
// =========================
app.post("/solicitacoes", authMiddleware, async (req, res) => {
  try {
    const dados = req.body;
    const usuarioIdSolicitante = Number(dados.usuario_id);

    // usuario_id = solicitante REAL.
    if (req.user.tipo !== "admin" && req.user.id !== usuarioIdSolicitante) {
      return res.status(403).json({
        erro: "Usuário não autorizado a criar solicitação para outro solicitante.",
      });
    }

    const nova = await prisma.solicitacao.create({
      data: {
        ...dados,
        usuario_id: usuarioIdSolicitante,
      },
    });

    res.json(nova);
  } catch (err) {
    console.error("Erro em POST /solicitacoes:", err);
    res.status(500).json({ erro: "Erro ao criar solicitação." });
  }
});

// =========================
// 🔰 ATUALIZAR SOLICITAÇÃO
// =========================
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

    // Se não for admin, só pode atualizar se for o solicitante
    if (req.user.tipo !== "admin" && existente.usuario_id !== req.user.id) {
      return res.status(403).json({
        erro: "Usuário não autorizado a alterar esta solicitação.",
      });
    }

    const atualizado = await prisma.solicitacao.update({
      where: { id: solicitacaoId },
      data: dados,
    });

    res.json(atualizado);
  } catch (err) {
    console.error("Erro em PUT /solicitacoes/:id:", err);
    res.status(500).json({ erro: "Erro ao atualizar solicitação." });
  }
});

// =========================
// 🔰 UPLOAD DE ARQUIVOS
// =========================
app.post(
  "/solicitacoes/:id/arquivos",
  authMiddleware,
  upload.single("arquivo"),
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
        return res
          .status(404)
          .json({ erro: "Solicitação não encontrada." });
      }

      if (req.user.tipo !== "admin" && solicitacao.usuario_id !== req.user.id) {
        return res.status(403).json({
          erro: "Usuário não autorizado a anexar arquivos nesta solicitação.",
        });
      }

      const registro = await prisma.solicitacao_arquivos.create({
        data: {
          solicitacao_id: solicitacaoId,
          tipo: tipo || "outro",
          original_name: file.originalname,
          mime_type: file.mimetype,
          path: file.filename,
        },
      });

      res.json(registro);
    } catch (err) {
      console.error("Erro em POST /solicitacoes/:id/arquivos:", err);
      res.status(500).json({ erro: "Erro ao enviar arquivo." });
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

    const arquivos = await prisma.solicitacao_arquivos.findMany({
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

    const registro = await prisma.solicitacao_arquivos.findUnique({
      where: { id: Number(id) },
    });

    if (!registro) {
      return res.status(404).json({ erro: "Arquivo não encontrado." });
    }

    const solicitacao = await prisma.solicitacao.findUnique({
      where: { id: registro.solicitacao_id },
    });

    if (!solicitacao) {
      return res.status(404).json({ erro: "Solicitação não encontrada." });
    }

    if (req.user.tipo !== "admin" && solicitacao.usuario_id !== req.user.id) {
      return res.status(403).json({
        erro: "Usuário não autorizado a baixar este arquivo.",
      });
    }

    const fullPath = path.join(uploadDir, registro.path);

    if (!fs.existsSync(fullPath)) {
      return res
        .status(410)
        .json({ erro: "Arquivo não está mais disponível." });
    }

    res.download(fullPath, registro.original_name);
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

    const registro = await prisma.solicitacao_arquivos.findUnique({
      where: { id: Number(id) },
    });

    if (!registro) {
      return res.status(404).json({ erro: "Arquivo não encontrado." });
    }

    const solicitacao = await prisma.solicitacao.findUnique({
      where: { id: registro.solicitacao_id },
    });

    if (!solicitacao) {
      return res.status(404).json({ erro: "Solicitação não encontrada." });
    }

    if (req.user.tipo !== "admin" && solicitacao.usuario_id !== req.user.id) {
      return res.status(403).json({
        erro: "Usuário não autorizado a remover este arquivo.",
      });
    }

    const fullPath = path.join(uploadDir, registro.path);

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
// 🔰 HISTÓRICO DE STATUS (POR SOLICITAÇÃO)
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

    await prisma.solicitacao_status_history.create({
      data: {
        solicitacao_id: Number(id),
        status,
        data: new Date(),
        origem: origem || "Sistema",
        obs: obs || null,
      },
    });

    res.json({ ok: true, atualizado });
  } catch (err) {
    console.error("Erro em PUT /solicitacoes/:id/status:", err);
    res.status(500).json({ erro: "Erro ao atualizar status." });
  }
});

// =========================
// 🔰 KANBAN (DINÂMICO — baseado na tabela STATUS) — ADMIN
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
    arquivos: true,       // ✅
    statusHistory: true,  // (se quiser usar no futuro)
    usuario: true,        // ✅ já traz o dono da solicitação
  },
});

    const grupos = {};
    statusList.forEach((s) => {
      grupos[s.nome] = [];
    });

    solicitacoes.forEach((s) => {
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
// 🔰 DASHBOARD (VERSÃO 3 — igual ao layout atual) — ADMIN
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

    const ultimas = await prisma.solicitacao.findMany({
      orderBy: { criado_em: "desc" },
      take: 10,
      include: {
  arquivos: true, // ✅
},
    });

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
// 🔰 HISTÓRICO GLOBAL DAS SOLICITAÇÕES (ADMIN)
// =========================
app.get("/historico", authMiddleware, adminOnly, async (req, res) => {
  try {
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
// 🔰 RELATÓRIOS — IRPF (ADMIN)
// =========================
app.get("/relatorios/irpf", authMiddleware, adminOnly, async (req, res) => {
  try {
    const dados = await prisma.solicitacao.findMany({
      orderBy: { criado_em: "desc" },
      include: {
  arquivos: true, // ✅
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
// 🔰 GERAR ESTRUTURA DO BANCO (TXT DINÂMICO) — ADMIN
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
