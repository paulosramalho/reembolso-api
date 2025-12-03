// index.js — versão recuperada com rotas internas

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const app = express();
const prisma = new PrismaClient();

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;

// CORS
app.use(express.json());

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:3000",
      process.env.APP_BASE_URL,
    ],
    credentials: true,
  })
);

// ------------------------------
// HEALTHCHECK
// ------------------------------
app.get("/health", async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: "ok" });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

// ------------------------------
// ROTA RAIZ
// ------------------------------
app.get("/", (req, res) => {
  res.send("API Reembolso rodando.");
});

// ------------------------------
// AUTENTICAÇÃO
// ------------------------------
app.post("/auth/login", async (req, res) => {
  const { email, senha } = req.body;

  const usuario = await prisma.usuario.findUnique({ where: { email } });

  if (!usuario)
    return res.status(400).json({ erro: "Usuário não encontrado" });

  const senhaOk = await bcrypt.compare(senha, usuario.senha_hash);
  if (!senhaOk)
    return res.status(400).json({ erro: "Senha inválida" });

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
});

// ------------------------------
// RESET DE SENHA — solicitação
// ------------------------------
app.post("/auth/reset-solicitar", async (req, res) => {
  const { email } = req.body;

  const usuario = await prisma.usuario.findUnique({ where: { email } });

  if (!usuario)
    return res.status(400).json({ erro: "Usuário não encontrado" });

  const token = Math.random().toString(36).substring(2, 15);
  const expires = new Date(Date.now() + 60 * 60 * 1000); // 1h

  await prisma.usuario.update({
    where: { id: usuario.id },
    data: {
      reset_token: token,
      reset_token_expires: expires,
    },
  });

  const resetLink = `${process.env.APP_BASE_URL}/resetar-senha/${token}`;

  // Envio e-mail
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

// ------------------------------
// RESET DE SENHA — confirmação
// ------------------------------
app.post("/auth/reset-confirmar", async (req, res) => {
  const { token, novaSenha } = req.body;

  const usuario = await prisma.usuario.findFirst({
    where: {
      reset_token: token,
      reset_token_expires: { gte: new Date() },
    },
  });

  if (!usuario)
    return res.status(400).json({ erro: "Token inválido ou expirado" });

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

// ------------------------------
// LISTAR USUÁRIOS
// ------------------------------
app.get("/usuarios/:id", async (req, res) => {
  const { id } = req.params;

  const usuario = await prisma.usuario.findUnique({
    where: { id: Number(id) },
  });

  if (!usuario) return res.status(404).json({ erro: "Não encontrado" });

  res.json(usuario);
});

// ------------------------------
// SOLICITAÇÕES
// ------------------------------

// Listar solicitações do usuário
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

// ------------------------------
// INICIAR SERVIDOR
// ------------------------------
app.listen(PORT, () => {
  console.log(`🚀 API Reembolso rodando na porta ${PORT}`);
});
