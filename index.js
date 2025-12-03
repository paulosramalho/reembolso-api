// index.js — API Reembolso completa estável 03/12

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

// Middlewares
app.use(express.json());

// CORS
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
      // Requisições sem origin (Postman, etc.)
      if (!origin) return callback(null, true);

      // Explicitamente permitidos
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      // Qualquer domínio da Vercel relacionado ao projeto
      if (origin.endsWith(".vercel.app") && origin.includes("controle-de-reembolso")) {
        return callback(null, true);
      }

      // Rejeita silenciosamente (sem lançar erro -> não dá 500)
      return callback(null, false);
    },
    credentials: true,
  })
);

// Upload config
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination(req, file, cb) {
    cb(null, uploadDir);
  },
  filename(req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, uniqueSuffix + ext);
  },
});

const upload = multer({ storage });

// Health
app.get("/health", async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Erro no /health:", err);
    res.status(500).json({ status: "error", message: "DB indisponível" });
  }
});

// Root
app.get("/", (req, res) => {
  res.send("API Reembolso rodando.");
});

// Auth login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, login, senha } = req.body;
    const identificador = email || login;

    if (!identificador || !senha) {
      return res
        .status(400)
        .json({ ok: false, mensagem: "Usuário e senha são obrigatórios." });
    }

    const usuario = await prisma.usuario.findFirst({
      where: {
        OR: [{ email: identificador }, { nome: identificador }],
      },
    });

    if (!usuario) {
      return res
        .status(400)
        .json({ ok: false, mensagem: "Usuário não encontrado." });
    }

    const senhaOk = await bcrypt.compare(senha, usuario.senha_hash);
    if (!senhaOk) {
      return res
        .status(400)
        .json({ ok: false, mensagem: "Usuário ou senha inválidos." });
    }

    if (!JWT_SECRET) {
      console.error("JWT_SECRET não definido");
      return res
        .status(500)
        .json({ ok: false, mensagem: "Erro de configuração do servidor." });
    }

    const token = jwt.sign(
      { id: usuario.id, tipo: usuario.tipo },
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

    // resposta bem ampla pra agradar qualquer lógica do front
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
      .json({ ok: false, mensagem: "Erro interno ao tentar fazer login." });
  }
});

// Reset senha - solicitar
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

// Alias para compatibilidade com o front: /auth/esqueci-senha
app.post("/auth/esqueci-senha", async (req, res) => {
  // Reaproveita a mesma lógica de reset-solicitar
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

// Reset senha - confirmar
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
      return res
        .status(400)
        .json({ erro: "Token inválido ou expirado." });
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

// Usuário por id
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

// Listar todos os usuários
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

// Listar descrições de despesas
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

// Listar status das solicitações
app.get("/status", async (req, res) => {
  try {
    const listaStatus = await prisma.$queryRaw`
      SELECT id, nome, descricao, ativo
      FROM status
      WHERE ativo = true
      ORDER BY id;
    `;

    res.json(listaStatus);
  } catch (err) {
    console.error("Erro em GET /status:", err);
    res.status(500).json({ erro: "Erro ao listar status." });
  }
});

// Listar solicitações do usuário
app.get("/solicitacoes/usuario/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const dados = await prisma.solicacao.findMany({
      where: { usuario_id: Number(id) },
      include: {
        arquivos: true,
        statusHistory: true,
      },
    });

    res.json(dados);
  } catch (err) {
    console.error("Erro em GET /solicitacoes/usuario/:id:", err);
    res.status(500).json({ erro: "Erro ao buscar solicitações." });
  }
});

// Criar solicitação
app.post("/solicitacoes", async (req, res) => {
  try {
    const dados = req.body;

    const nova = await prisma.solicitacao.create({
      data: {
        ...dados,
        usuario_id: Number(dados.usuario_id),
      },
    });

    res.json(nova);
  } catch (err) {
    console.error("Erro em POST /solicitacoes:", err);
    res.status(500).json({ erro: "Erro ao criar solicitação." });
  }
});

// Atualizar solicitação
app.put("/solicitacoes/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const dados = req.body;

    const atualizado = await prisma.solicitacao.update({
      where: { id: Number(id) },
      data: dados,
    });

    res.json(atualizado);
  } catch (err) {
    console.error("Erro em PUT /solicitacoes/:id:", err);
    res.status(500).json({ erro: "Erro ao atualizar solicitação." });
  }
});

// Upload de arquivo
app.post(
  "/solicitacoes/:id/arquivos",
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

      const registro = await prisma.solicitacaoArquivo.create({
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

// Listar arquivos
app.get("/solicitacoes/:id/arquivos", async (req, res) => {
  try {
    const solicitacaoId = Number(req.params.id);

    const arquivos = await prisma.solicitacaoArquivo.findMany({
      where: { solicitacao_id: solicitacaoId },
      orderBy: { created_at: "desc" },
    });

    res.json(arquivos);
  } catch (err) {
    console.error("Erro em GET /solicitacoes/:id/arquivos:", err);
    res.status(500).json({ erro: "Erro ao listar arquivos." });
  }
});

// Download arquivo
app.get("/arquivos/:id/download", async (req, res) => {
  try {
    const { id } = req.params;

    const registro = await prisma.solicitacaoArquivo.findUnique({
      where: { id: Number(id) },
    });

    if (!registro) {
      return res.status(404).json({ erro: "Arquivo não encontrado." });
    }

    const fullPath = path.join(uploadDir, registro.path);

    if (!fs.existsSync(fullPath)) {
      return res
        .status(410)
        .json({ erro: "Arquivo não está mais disponível no servidor." });
    }

    res.download(fullPath, registro.original_name);
  } catch (err) {
    console.error("Erro em GET /arquivos/:id/download:", err);
    res.status(500).json({ erro: "Erro ao fazer download do arquivo." });
  }
});

// Remover arquivo
app.delete("/arquivos/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const registro = await prisma.solicitacaoArquivo.findUnique({
      where: { id: Number(id) },
    });

    if (!registro) {
      return res.status(404).json({ erro: "Arquivo não encontrado." });
    }

    const fullPath = path.join(uploadDir, registro.path);

    if (fs.existsSync(fullPath)) {
      fs.unlinkSync(fullPath);
    }

    await prisma.solicitacaoArquivo.delete({
      where: { id: Number(id) },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erro em DELETE /arquivos/:id:", err);
    res.status(500).json({ erro: "Erro ao remover arquivo." });
  }
});

// Middleware de erro genérico
app.use((err, req, res, next) => {
  console.error("Erro não tratado:", err);
  res.status(500).json({ error: "Erro interno do servidor" });
});

// Start
app.listen(PORT, () => {
  console.log(`🚀 API Reembolso rodando na porta ${PORT}`);
});
