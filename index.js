// index.js — API Reembolso completa (com anexos) 03/12/25 - 01:34h

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

// ───────────── MIDDLEWARES BÁSICOS ─────────────

app.use(express.json());

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
      if (!origin) return callback(null, true); // ex: Postman
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Não permitido pelo CORS"), false);
    },
    credentials: true,
  })
);

// ───────────── CONFIG DE UPLOAD (ANEXOS) ─────────────

const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix =
      Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, uniqueSuffix + ext);
  },
});

const upload = multer({ storage });

// ───────────── HEALTH & ROOT ─────────────

app.get("/health", async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Erro no healthcheck:", err);
    res.status(500).json({ status: "error", message: "DB indisponível" });
  }
});

app.get("/", (req, res) => {
  res.send("API Reembolso rodando.");
});

// ───────────── AUTENTICAÇÃO ─────────────

app.post("/auth/login", async (req, res) => {
  try {
    const { email, login, senha } = req.body;

    // O front pode mandar "email" ou "login" (email ou nome)
    const identificador = email || login;

    if (!identificador || !senha) {
      return res
        .status(400)
        .json({ erro: "Usuário e senha são obrigatórios." });
    }

    // Procura por e-mail ou por nome
    const usuario = await prisma.usuario.findFirst({
      where: {
        OR: [
          { email: identificador },
          { nome: identificador },
        ],
      },
    });

    if (!usuario) {
      return res.status(400).json({ erro: "Usuário não encontrado." });
    }

    const senhaOk = await bcrypt.compare(senha, usuario.senha_hash);
    if (!senhaOk) {
      return res.status(400).json({ erro: "Usuário ou senha inválidos." });
    }

    if (!JWT_SECRET) {
      console.error("⚠️ JWT_SECRET não definido nas variáveis de ambiente.");
      return res
        .status(500)
        .json({ erro: "Erro de configuração do servidor." });
    }

    const token = jwt.sign(
      { id: usuario.id, tipo: usuario.tipo },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
        cpfcnpj: usuario.cpfcnpj,
        telefone: usuario.telefone,
        tipo: usuario.tipo,
      },
    });
  } catch (err) {
    console.error("Erro em /auth/login:", err);
    res
      .status(500)
      .json({ erro: "Erro interno ao tentar fazer login." });
  }
});

// ───────────── RESET DE SENHA ─────────────

// Solicitar reset
app.post("/auth/reset-solicitar", async (req, res) => {
  const { email } = req.body;

  const usuario = await prisma.usuario.findUnique({ where: { email } });

  if (!usuario) {
    return res.status(400).json({ erro: "Usuário não encontrado" });
  }

  const token = Math.random().toString(36).substring(2, 15);
  const expires = new Date(Date.now() + 60 * 60 * 1000); // 1h

  await prisma.usuario.update({
    where: { id: usuario.id },
    data: {
      reset_token: token,
      reset_token_expires: expires,
    },
  });

  const resetLink = `${APP_BASE_URL.replace(/\/$/, "")}/resetar-senha/${token}`;

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
});

// Confirmar reset
app.post("/auth/reset-confirmar", async (req, res) => {
  const { token, novaSenha } = req.body;

  const usuario = await prisma.usuario.findFirst({
    where: {
      reset_token: token,
      reset_token_expires: { gte: new Date() },
    },
  });

  if (!usuario) {
    return res.status(400).json({ erro: "Token inválido ou expirado" });
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
});

// ───────────── USUÁRIOS ─────────────

app.get("/usuarios/:id", async (req, res) => {
  const { id } = req.params;

  const usuario = await prisma.usuario.findUnique({
    where: { id: Number(id) },
  });

  if (!usuario) {
    return res.status(404).json({ erro: "Usuário não encontrado" });
  }

  res.json(usuario);
});

// (poderiam existir mais rotas de usuários aqui
// criar, listar todos, etc., se você quiser depois)

// ───────────── SOLICITAÇÕES ─────────────

// Listar solicitações de um usuário
app.get("/solicitacoes/usuario/:id", async (req, res) => {
  const { id } = req.params;

  const dados = await prisma.solicitacao.findMany({
    where: { usuario_id: Number(id) },
    include: {
      arquivos: true,
      statusHistory: true,
    },
  });

  res.json(dados);
});

// Criar nova solicitação
app.post("/solicitacoes", async (req, res) => {
  const dados = req.body;

  const nova = await prisma.solicitacao.create({
    data: {
      ...dados,
      usuario_id: Number(dados.usuario_id),
    },
  });

  res.json(nova);
});

// Atualizar solicitação
app.put("/solicitacoes/:id", async (req, res) => {
  const { id } = req.params;
  const dados = req.body;

  const atualizado = await prisma.solicitacao.update({
    where: { id: Number(id) },
    data: dados,
  });

  res.json(atualizado);
});

// ───────────── ANEXOS / ARQUIVOS ─────────────

// Upload de um arquivo para uma solicitação
// campo do formulário: "arquivo"
app.post(
  "/solicitacoes/:id/arquivos",
  upload.single("arquivo"),
  async (req, res) => {
    const solicitacaoId = Number(req.params.id);
    const { tipo } = req.body;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ erro: "Nenhum arquivo enviado" });
    }

    // Garante que a solicitação existe
    const solicitacao = await prisma.solicitacao.findUnique({
      where: { id: solicitacaoId },
    });

    if (!solicitacao) {
      return res.status(404).json({ erro: "Solicitação não encontrada" });
    }

    const registro = await prisma.solicitacaoArquivo.create({
      data: {
        solicitacao_id: solicitacaoId,
        tipo: tipo || "outro",
        original_name: file.originalname,
        mime_type: file.mimetype,
        path: file.filename, // só o nome; o caminho base é uploadDir
      },
    });

    res.json(registro);
  }
);

// Listar arquivos de uma solicitação
app.get("/solicitacoes/:id/arquivos", async (req, res) => {
  const solicitacaoId = Number(req.params.id);

  const arquivos = await prisma.solicitacaoArquivo.findMany({
    where: { solicitacao_id: solicitacaoId },
    orderBy: { created_at: "desc" },
  });

  res.json(arquivos);
});

// Download de um arquivo pelo id do registro
app.get("/arquivos/:id/download", async (req, res) => {
  const { id } = req.params;

  const registro = await prisma.solicitacaoArquivo.findUnique({
    where: { id: Number(id) },
  });

  if (!registro) {
    return res.status(404).json({ erro: "Arquivo não encontrado" });
  }

  const fullPath = path.join(uploadDir, registro.path);

  if (!fs.existsSync(fullPath)) {
    return res
      .status(410)
      .json({ erro: "Arquivo não está mais disponível no servidor" });
  }

  res.download(fullPath, registro.original_name);
});

// Remover arquivo
app.delete("/arquivos/:id", async (req, res) => {
  const { id } = req.params;

  const registro = await prisma.solicitacaoArquivo.findUnique({
    where: { id: Number(id) },
  });

  if (!registro) {
    return res.status(404).json({ erro: "Arquivo não encontrado" });
  }

  const fullPath = path.join(uploadDir, registro.path);

  // apaga arquivo físico (se existir)
  if (fs.existsSync(fullPath)) {
    fs.unlinkSync(fullPath);
  }

  await prisma.solicitacaoArquivo.delete({
    where: { id: Number(id) },
  });

  res.json({ ok: true });
});

// ───────────── ERRO GENÉRICO ─────────────

app.use((err, req, res, next) => {
  console.error("Erro não tratado:", err);
  res.status(500).json({ error: "Erro interno do servidor" });
});

// ───────────── START SERVER ─────────────

app.listen(PORT, () => {
  console.log(`🚀 API Reembolso rodando na porta ${PORT}`);
});
