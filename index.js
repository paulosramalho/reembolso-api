// index.js — API Reembolso COMPLETA e ATUALIZADA 03/12/25 - 16:08h
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

console.log("🔧 SMTP DEBUG:", {
  host: process.env.SMTP_HOST,
  user: process.env.SMTP_USER,
  hasPass: !!process.env.SMTP_PASS,
});

// =========================
// 🔰 CONFIGURAÇÃO DE CORS
// =========================
app.use(
  cors({
    origin: (origin, callback) => {
      callback(null, true);
    },
    credentials: true,
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =========================
// 🔰 DIRETÓRIO DE UPLOADS
// =========================
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// =========================
// 🔰 MULTER (UPLOAD)
// =========================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix =
      Date.now() + "-" + Math.round(Math.random() * 1e9).toString(36);
    const ext = path.extname(file.originalname) || "";
    cb(null, `${uniqueSuffix}${ext}`);
  },
});

const upload = multer({ storage });

// =========================
// 🔰 AUTENTICAÇÃO
// =========================

function gerarToken(usuario) {
  return jwt.sign(
    { id: usuario.id, tipo: usuario.tipo },
    JWT_SECRET,
    { expiresIn: "8h" }
  );
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || req.headers.Authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ erro: "Token não fornecido." });
  }

  const token = authHeader.replace("Bearer ", "").trim();

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error("Erro ao verificar token:", err);
    return res.status(401).json({ erro: "Token inválido ou expirado." });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.tipo !== "admin") {
    return res.status(403).json({ erro: "Somente admin pode acessar." });
  }
  next();
}

// =========================
// 🔰 NODEMAILER (SMTP)
// =========================
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: Number(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// =========================
// 🔰 LOGIN
// =========================
app.post("/login", async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res.status(400).json({ erro: "Email e senha são obrigatórios." });
    }

    const usuario = await prisma.usuario.findUnique({
      where: { email },
    });

    if (!usuario) {
      return res.status(401).json({ erro: "Credenciais inválidas." });
    }

    const senhaOk = await bcrypt.compare(senha, usuario.senha_hash);

    if (!senhaOk) {
      return res.status(401).json({ erro: "Credenciais inválidas." });
    }

    const token = gerarToken(usuario);

    const usuarioSeguro = {
      id: usuario.id,
      nome: usuario.nome,
      email: usuario.email,
      tipo: usuario.tipo,
      createdAt: usuario.criado_em,
    };

    return res.json({ token, usuario: usuarioSeguro });
  } catch (err) {
    console.error("Erro em POST /login:", err);
    res.status(500).json({ erro: "Erro ao efetuar login." });
  }
});

// =========================
// 🔰 LISTAR USUÁRIOS (ADMIN)
// =========================
app.get("/usuarios", authMiddleware, adminOnly, async (req, res) => {
  try {
    const usuarios = await prisma.usuario.findMany({
      orderBy: { criado_em: "desc" },
    });

    const mapped = usuarios.map((u) => ({
      id: u.id,
      nome: u.nome,
      email: u.email,
      tipo: u.tipo,
      createdAt: u.criado_em,
    }));

    res.json(mapped);
  } catch (err) {
    console.error("Erro em GET /usuarios:", err);
    res.status(500).json({ erro: "Erro ao listar usuários." });
  }
});

// =========================
// 🔰 CRIAR USUÁRIO (ADMIN)
// =========================
app.post("/usuarios", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { nome, email, senha, tipo } = req.body;

    if (!nome || !email || !senha) {
      return res
        .status(400)
        .json({ erro: "Nome, email e senha são obrigatórios." });
    }

    const senha_hash = await bcrypt.hash(senha, 10);

    const usuario = await prisma.usuario.create({
      data: {
        nome,
        email,
        senha_hash,
        tipo: tipo || "usuario",
      },
    });

    res.json({
      id: usuario.id,
      nome: usuario.nome,
      email: usuario.email,
      tipo: usuario.tipo,
      createdAt: usuario.criado_em,
    });
  } catch (err) {
    console.error("Erro em POST /usuarios:", err);
    res.status(500).json({ erro: "Erro ao criar usuário." });
  }
});

// =========================
// 🔰 DESPESAS
// =========================
app.get("/despesas", authMiddleware, async (req, res) => {
  try {
    const despesas = await prisma.despesa.findMany({
      orderBy: { id: "asc" },
    });
    res.json(despesas);
  } catch (err) {
    console.error("Erro em GET /despesas:", err);
    res.status(500).json({ erro: "Erro ao listar despesas." });
  }
});

app.post("/despesas", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { nome, descricao, ativo } = req.body;

    if (!nome) {
      return res.status(400).json({ erro: "Nome é obrigatório." });
    }

    const despesa = await prisma.despesa.create({
      data: {
        nome,
        descricao: descricao || null,
        ativo: ativo !== undefined ? !!ativo : true,
      },
    });

    res.json(despesa);
  } catch (err) {
    console.error("Erro em POST /despesas:", err);
    res.status(500).json({ erro: "Erro ao criar despesa." });
  }
});

app.put("/despesas/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const despesaId = Number(id);

    if (!despesaId || Number.isNaN(despesaId)) {
      return res.status(400).json({ erro: "ID inválido." });
    }

    const { nome, descricao, ativo } = req.body;

    const despesa = await prisma.despesa.update({
      where: { id: despesaId },
      data: {
        nome,
        descricao,
        ativo: ativo !== undefined ? !!ativo : undefined,
      },
    });

    res.json(despesa);
  } catch (err) {
    console.error("Erro em PUT /despesas/:id:", err);
    res.status(500).json({ erro: "Erro ao atualizar despesa." });
  }
});

app.delete("/despesas/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const despesaId = Number(req.params.id);

    if (!despesaId || Number.isNaN(despesaId)) {
      return res.status(400).json({ erro: "ID inválido." });
    }

    await prisma.despesa.delete({
      where: { id: despesaId },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erro em DELETE /despesas/:id:", err);
    res.status(500).json({ erro: "Erro ao excluir despesa." });
  }
});

// =========================
