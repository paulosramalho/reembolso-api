// index.js — API Reembolso COMPLETA e ATUALIZADA 05/12/25 - 01:52h
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
  prisma.solicitacaoArquivo ||      // ex: model Solicitacao_arquivos
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

// Helper para acessar o modelo de histórico de status, qualquer que seja o nome no Prisma
function getHistoricoModel() {
  const Historico =
    prisma.solicitacaoStatusHistory ||
    prisma.SolicitacaoStatusHistory ||
    null;

  if (!Historico) {
    console.error(
      "Modelo SolicitacaoStatusHistory não encontrado no Prisma Client."
    );
  }

  return Historico;
}

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "segredo-super-seguro";

// Diretório de uploads para arquivos de NF, comprovantes, etc.
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configuração do Multer (upload de arquivos)
const storage = multer.diskStorage({
  destination(req, file, cb) {
    cb(null, uploadDir);
  },
  filename(req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    // Normaliza o nome do arquivo, removendo caracteres especiais e espaços
    const originalName = file.originalname
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-zA-Z0-9.\-_]/g, "_");

    cb(null, `${uniqueSuffix}-${originalName}`);
  },
});

const upload = multer({ storage });

// =========================
// 🔰 MIDDLEWARES GERAIS
// =========================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const APP_BASE_URL = process.env.APP_BASE_URL || "http://localhost:5173";

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
      console.warn(`Origem não permitida pelo CORS: ${origin}`);
      return callback(new Error("CORS não permitido para esta origem"), false);
    },
    credentials: true,
  })
);

// Servir arquivos estáticos de uploads
app.use("/uploads", express.static(uploadDir));

// =========================
// 🔰 LOG SIMPLES DE REQUESTS
// =========================
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// =========================
// 🔰 FUNÇÕES AUXILIARES
// =========================

// Normaliza número (string com vírgula, etc.) para número JS
function normalizarNumero(valor) {
  if (valor === null || valor === undefined || valor === "") return null;
  if (typeof valor === "number") return valor;
  if (typeof valor !== "string") return null;

  const limpo = valor.replace(/\./g, "").replace(",", ".");
  const num = Number(limpo);
  if (Number.isNaN(num)) return null;
  return num;
}

// Normaliza data vinda do front (YYYY-MM-DD, etc.) para Date
function normalizarData(valor) {
  if (!valor) return null;
  if (valor instanceof Date && !Number.isNaN(valor.getTime())) return valor;

  if (typeof valor === "string") {
    const parts = valor.split("-");
    if (parts.length === 3) {
      const [ano, mes, dia] = parts.map((p) => parseInt(p, 10));
      if (!Number.isNaN(ano) && !Number.isNaN(mes) && !Number.isNaN(dia)) {
        return new Date(ano, mes - 1, dia, 12, 0, 0);
      }
    }
    const outraData = new Date(valor);
    if (!Number.isNaN(outraData.getTime())) {
      return outraData;
    }
  }
  return null;
}

// =========================
// 🔰 AUTENTICAÇÃO (JWT)
// =========================
function gerarToken(usuario) {
  const payload = {
    id: usuario.id,
    email: usuario.email,
    nome: usuario.nome,
    tipo: usuario.tipo,
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "12h" });
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res
      .status(401)
      .json({ erro: "Token de autenticação não fornecido." });
  }

  const [, token] = authHeader.split(" ");
  if (!token) {
    return res.status(401).json({ erro: "Token malformado." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (err) {
    console.error("Erro ao verificar token:", err);
    return res.status(401).json({ erro: "Token inválido ou expirado." });
  }
}

// Middleware para admin
function adminOnly(req, res, next) {
  if (req.user?.tipo !== "admin") {
    return res.status(403).json({ erro: "Acesso restrito a administradores." });
  }
  return next();
}

// =========================
// 🔰 ROTA RAIZ
// =========================
app.get("/", (req, res) => {
  res.json({
    mensagem: "API Reembolso rodando.",
    APP_BASE_URL,
    PORT,
  });
});

// =========================
// 🔰 AUTENTICAÇÃO & USUÁRIOS
// =========================

// Login (e-mail + senha)
app.post("/auth/login", async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res
        .status(400)
        .json({ erro: "E-mail e senha são obrigatórios." });
    }

    const usuario = await prisma.usuario.findUnique({
      where: { email },
    });

    if (!usuario) {
      return res.status(401).json({ erro: "Usuário não encontrado." });
    }

    const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
    if (!senhaValida) {
      return res.status(401).json({ erro: "Senha inválida." });
    }

    const token = gerarToken(usuario);

    const usuarioSemHash = {
      id: usuario.id,
      nome: usuario.nome,
      email: usuario.email,
      cpf: usuario.cpf,
      telefone: usuario.telefone,
      tipo: usuario.tipo,
      ativo: usuario.ativo,
      criado_em: usuario.criado_em,
      atualizado_em: usuario.atualizado_em,
    };

    res.json({
      token,
      usuario: usuarioSemHash,
    });
  } catch (err) {
    console.error("Erro em /auth/login:", err);
    res.status(500).json({ erro: "Erro ao efetuar login." });
  }
});

// "Esqueci minha senha" - Envia e-mail com token de redefinição
app.post("/auth/esqueci-senha", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ erro: "E-mail é obrigatório." });
    }

    const usuario = await prisma.usuario.findUnique({ where: { email } });
    if (!usuario) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    const resetToken = jwt.sign({ id: usuario.id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    await prisma.usuario.update({
      where: { id: usuario.id },
      data: {
        reset_token: resetToken,
        reset_token_expira_em: new Date(Date.now() + 60 * 60 * 1000),
      },
    });

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || "smtp.gmail.com",
      port: Number(process.env.SMTP_PORT) || 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER || "seu_email@gmail.com",
        pass: process.env.SMTP_PASS || "sua_senha",
      },
    });

    const resetLink =
      process.env.FRONTEND_RESET_URL ||
      `${APP_BASE_URL}/resetar-senha?token=${resetToken}`;

    await transporter.sendMail({
      from: process.env.SMTP_FROM || "no-reply@seusistema.com",
      to: email,
      subject: "Redefinição de senha - Controle de Reembolso",
      text: `Olá, ${usuario.nome}!\n\nVocê solicitou a redefinição de senha. Acesse o link abaixo para criar uma nova senha (válido por 1 hora):\n\n${resetLink}\n\nSe você não solicitou essa redefinição, ignore este e-mail.`,
      html: `<p>Olá, <strong>${usuario.nome}</strong>!</p>
             <p>Você solicitou a redefinição de senha. Acesse o link abaixo para criar uma nova senha (válido por 1 hora):</p>
             <p><a href="${resetLink}">${resetLink}</a></p>
             <p>Se você não solicitou essa redefinição, ignore este e-mail.</p>`,
    });

    res.json({ mensagem: "E-mail de redefinição enviado com sucesso." });
  } catch (err) {
    console.error("Erro em /auth/esqueci-senha:", err);
    res.status(500).json({ erro: "Erro ao processar solicitação de senha." });
  }
});

// Redefinir senha (com token)
app.post("/auth/resetar-senha", async (req, res) => {
  try {
    const { token, novaSenha } = req.body;

    if (!token || !novaSenha) {
      return res
        .status(400)
        .json({ erro: "Token e nova senha são obrigatórios." });
    }

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      console.error("Token de redefinição inválido ou expirado:", err);
      return res
        .status(400)
        .json({ erro: "Token inválido ou expirado para redefinição." });
    }

    const usuario = await prisma.usuario.findUnique({
      where: { id: payload.id },
    });
    if (!usuario) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    if (!usuario.reset_token || usuario.reset_token !== token) {
      return res
        .status(400)
        .json({ erro: "Token de redefinição não confere." });
    }

    if (
      !usuario.reset_token_expira_em ||
      usuario.reset_token_expira_em < new Date()
    ) {
      return res.status(400).json({ erro: "Token de redefinição expirado." });
    }

    const hash = await bcrypt.hash(novaSenha, 10);

    await prisma.usuario.update({
      where: { id: usuario.id },
      data: {
        senha_hash: hash,
        reset_token: null,
        reset_token_expira_em: null,
      },
    });

    res.json({ mensagem: "Senha redefinida com sucesso." });
  } catch (err) {
    console.error("Erro em /auth/resetar-senha:", err);
    res.status(500).json({ erro: "Erro ao redefinir senha." });
  }
});

// =========================
// 🔰 CRUD DE USUÁRIOS (ADMIN)
// =========================

// Lista de usuários
app.get("/usuarios", authMiddleware, adminOnly, async (req, res) => {
  try {
    const usuarios = await prisma.usuario.findMany({
      orderBy: { id: "asc" },
    });

    res.json(usuarios);
  } catch (err) {
    console.error("Erro em GET /usuarios:", err);
    res.status(500).json({ erro: "Erro ao buscar usuários." });
  }
});

// Detalhes do "Meu Perfil"
app.get("/usuarios/me", authMiddleware, async (req, res) => {
  try {
    const usuario = await prisma.usuario.findUnique({
      where: { id: req.user.id },
    });

    if (!usuario) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    const usuarioSemHash = {
      id: usuario.id,
      nome: usuario.nome,
      email: usuario.email,
      cpf: usuario.cpf,
      telefone: usuario.telefone,
      tipo: usuario.tipo,
      ativo: usuario.ativo,
      criado_em: usuario.criado_em,
      atualizado_em: usuario.atualizado_em,
    };

    res.json(usuarioSemHash);
  } catch (err) {
    console.error("Erro em GET /usuarios/me:", err);
    res.status(500).json({ erro: "Erro ao buscar perfil do usuário." });
  }
});

// Atualizar "Meu Perfil"
app.put("/usuarios/me", authMiddleware, async (req, res) => {
  try {
    const { nome, telefone } = req.body;

    const atualizado = await prisma.usuario.update({
      where: { id: req.user.id },
      data: {
        nome: nome || undefined,
        telefone: telefone || undefined,
      },
    });

    const usuarioSemHash = {
      id: atualizado.id,
      nome: atualizado.nome,
      email: atualizado.email,
      cpf: atualizado.cpf,
      telefone: atualizado.telefone,
      tipo: atualizado.tipo,
      ativo: atualizado.ativo,
      criado_em: atualizado.criado_em,
      atualizado_em: atualizado.atualizado_em,
    };

    res.json(usuarioSemHash);
  } catch (err) {
    console.error("Erro em PUT /usuarios/me:", err);
    res.status(500).json({ erro: "Erro ao atualizar perfil do usuário." });
  }
});

// Criar usuário (ADMIN)
app.post("/usuarios", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { nome, email, cpf, telefone, senha, tipo, ativo } = req.body;

    if (!nome || !email || !senha) {
      return res.status(400).json({
        erro: "Nome, e-mail e senha são obrigatórios.",
      });
    }

    const existente = await prisma.usuario.findUnique({
      where: { email },
    });
    if (existente) {
      return res.status(400).json({ erro: "E-mail já cadastrado." });
    }

    const hash = await bcrypt.hash(senha, 10);

    const novo = await prisma.usuario.create({
      data: {
        nome,
        email,
        cpf: cpf || null,
        telefone: telefone || null,
        senha_hash: hash,
        tipo: tipo || "user",
        ativo: ativo !== undefined ? !!ativo : true,
      },
    });

    const usuarioSemHash = {
      id: novo.id,
      nome: novo.nome,
      email: novo.email,
      cpf: novo.cpf,
      telefone: novo.telefone,
      tipo: novo.tipo,
      ativo: novo.ativo,
      criado_em: novo.criado_em,
      atualizado_em: novo.atualizado_em,
    };

    res.status(201).json(usuarioSemHash);
  } catch (err) {
    console.error("Erro em POST /usuarios:", err);
    res.status(500).json({ erro: "Erro ao criar usuário." });
  }
});

// Atualizar usuário (ADMIN)
app.put("/usuarios/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { nome, email, cpf, telefone, senha, tipo, ativo } = req.body;

    const usuarioId = Number(id);

    const existente = await prisma.usuario.findUnique({
      where: { id: usuarioId },
    });
    if (!existente) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    const dataAtualizar = {
      nome: nome || existente.nome,
      email: email || existente.email,
      cpf: cpf || existente.cpf,
      telefone: telefone || existente.telefone,
      tipo: tipo || existente.tipo,
      ativo:
        ativo !== undefined && ativo !== null
          ? !!ativo
          : existente.ativo,
    };

    if (senha) {
      dataAtualizar.senha_hash = await bcrypt.hash(senha, 10);
    }

    const atualizado = await prisma.usuario.update({
      where: { id: usuarioId },
      data: dataAtualizar,
    });

    const usuarioSemHash = {
      id: atualizado.id,
      nome: atualizado.nome,
      email: atualizado.email,
      cpf: atualizado.cpf,
      telefone: atualizado.telefone,
      tipo: atualizado.tipo,
      ativo: atualizado.ativo,
      criado_em: atualizado.criado_em,
      atualizado_em: atualizado.atualizado_em,
    };

    res.json(usuarioSemHash);
  } catch (err) {
    console.error("Erro em PUT /usuarios/:id:", err);
    res.status(500).json({ erro: "Erro ao atualizar usuário." });
  }
});

// Deletar usuário (ADMIN)
app.delete("/usuarios/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const usuarioId = Number(id);

    const existente = await prisma.usuario.findUnique({
      where: { id: usuarioId },
    });
    if (!existente) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    await prisma.usuario.delete({
      where: { id: usuarioId },
    });

    res.json({ mensagem: "Usuário removido com sucesso." });
  } catch (err) {
    console.error("Erro em DELETE /usuarios/:id:", err);
    res.status(500).json({ erro: "Erro ao remover usuário." });
  }
});

// =========================
// 🔰 DESCRIÇÕES DE DESPESAS
// =========================
app.get("/descricoes", authMiddleware, async (req, res) => {
  try {
    const descricoes = await prisma.descricao.findMany({
      where: { ativo: true },
      orderBy: { descricao: "asc" },
    });

    res.json(descricoes);
  } catch (err) {
    console.error("Erro em GET /descricoes:", err);
    res.status(500).json({ erro: "Erro ao buscar descrições." });
  }
});

// =========================
// 🔰 STATUS DE SOLICITAÇÕES
// =========================
app.get("/status", authMiddleware, async (req, res) => {
  try {
    const statusList = await prisma.status.findMany({
      where: { ativo: true },
      orderBy: { id: "asc" },
    });

    res.json(statusList);
  } catch (err) {
    console.error("Erro em GET /status:", err);
    res.status(500).json({ erro: "Erro ao buscar status." });
  }
});

// =========================
// 🔰 SOLICITAÇÕES
// =========================

// Campos permitidos para criação/edição de solicitação
const camposPermitidos = [
  "usuario_id",
  "descricao_id",
  "numero_nf",
  "data_nf",
  "valor_nf",
  "emitente_nome",
  "emitente_doc",
  "beneficiario_nome",
  "beneficiario_doc",
  "status",
  "data_solicitacao",
];

// Campos numéricos que devem ser normalizados
const camposNumericos = ["valor_nf"];

// Campos de data
const camposData = ["data_nf", "data_solicitacao"];

// Listar solicitações (com filtros básicos)
app.get("/solicitacoes", authMiddleware, async (req, res) => {
  try {
    const { status, usuario_id } = req.query;

    const where = {};

    if (status) {
      where.status = status;
    }

    if (usuario_id) {
      where.usuario_id = Number(usuario_id);
    } else if (req.user.tipo !== "admin") {
      where.usuario_id = req.user.id;
    }

    const solicitacoes = await prisma.solicitacao.findMany({
      where,
      orderBy: { criado_em: "desc" },
      include: {
        usuario: true,
        descricao: true,
        arquivos: true,
      },
    });

    const resultado = solicitacoes.map((sol) => ({
      id: sol.id,
      usuario_id: sol.usuario_id,
      solicitante_nome: sol.usuario?.nome || null,
      solicitante_email: sol.usuario?.email || null,
      descricao_id: sol.descricao_id,
      descricao_nome: sol.descricao?.descricao || null,
      numero_nf: sol.numero_nf,
      data_nf: sol.data_nf,
      valor_nf: sol.valor_nf,
      emitente_nome: sol.emitente_nome,
      emitente_doc: sol.emitente_doc,
      beneficiario_nome: sol.beneficiario_nome,
      beneficiario_doc: sol.beneficiario_doc,
      status: sol.status,
      data_solicitacao: sol.data_solicitacao,
      criado_em: sol.criado_em,
      atualizado_em: sol.atualizado_em,
      arquivos: sol.arquivos || [],
    }));

    res.json(resultado);
  } catch (err) {
    console.error("Erro em GET /solicitacoes:", err);
    res.status(500).json({ erro: "Erro ao buscar solicitações." });
  }
});

// Detalhe de uma solicitação
app.get("/solicitacoes/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const solicitacaoId = Number(id);

    const solicitacao = await prisma.solicitacao.findUnique({
      where: { id: solicitacaoId },
      include: {
        usuario: true,
        descricao: true,
        arquivos: true,
      },
    });

    if (!solicitacao) {
      return res.status(404).json({ erro: "Solicitação não encontrada." });
    }

    if (req.user.tipo !== "admin" && solicitacao.usuario_id !== req.user.id) {
      return res.status(403).json({
        erro: "Usuário não autorizado a ver esta solicitação.",
      });
    }

    const resultado = {
      id: solicitacao.id,
      usuario_id: solicitacao.usuario_id,
      solicitante_nome: solicitacao.usuario?.nome || null,
      solicitante_email: solicitacao.usuario?.email || null,
      descricao_id: solicitacao.descricao_id,
      descricao_nome: solicitacao.descricao?.descricao || null,
      numero_nf: solicitacao.numero_nf,
      data_nf: solicitacao.data_nf,
      valor_nf: solicitacao.valor_nf,
      emitente_nome: solicitacao.emitente_nome,
      emitente_doc: solicitacao.emitente_doc,
      beneficiario_nome: solicitacao.beneficiario_nome,
      beneficiario_doc: solicitacao.beneficiario_doc,
      status: solicitacao.status,
      data_solicitacao: solicitacao.data_solicitacao,
      criado_em: solicitacao.criado_em,
      atualizado_em: solicitacao.atualizado_em,
      arquivos: solicitacao.arquivos || [],
    };

    res.json(resultado);
  } catch (err) {
    console.error("Erro em GET /solicitacoes/:id:", err);
    res.status(500).json({ erro: "Erro ao buscar solicitação." });
  }
});

// Criar nova solicitação
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

      if (campo === "usuario_id") continue;

      let valor = dados[campo];

      if (valor === undefined || valor === null || valor === "") continue;

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

    // 🔹 Grava histórico inicial de status ("Em análise" ou status definido)
    const dataHistorico =
      dados.data ||
      dados.data_solicitacao ||
      dataCriar.data_solicitacao ||
      new Date();

    const Historico = getHistoricoModel();
    if (Historico) {
      try {
        await Historico.create({
          data: {
            solicitacao_id: nova.id,
            status: nova.status || dataCriar.status || "Em análise",
            data: dataHistorico,
            origem: "Criação",
            obs: null,
          },
        });
      } catch (errHist) {
        console.error(
          "Erro ao gravar histórico inicial da solicitação:",
          errHist
        );
      }
    }

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

    const statusAntes = existente.status;

    if (req.user.tipo !== "admin" && existente.usuario_id !== req.user.id) {
      return res.status(403).json({
        erro: "Usuário não autorizado a alterar esta solicitação.",
      });
    }

    const dataAtualizar = {};
    let statusMudou = false;

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
      const novoStatus = dataAtualizar.status;
      if (novoStatus && novoStatus !== statusAntes) {
        statusMudou = true;
      }
    }

    if (Object.keys(dataAtualizar).length === 0) {
      return res.json(existente);
    }

    const atualizado = await prisma.solicitacao.update({
      where: { id: solicitacaoId },
      data: dataAtualizar,
    });

    // 🔹 Se o status mudou (via edição genérica), registra no histórico
    if (statusMudou) {
      const Historico = getHistoricoModel();
      if (Historico) {
        try {
          const dataHistorico =
            dados.data ||
            dados.data_solicitacao ||
            atualizado.data_ultima_mudanca ||
            new Date();

          await Historico.create({
            data: {
              solicitacao_id: solicitacaoId,
              status: atualizado.status,
              data: dataHistorico,
              origem: "Edição",
              obs: null,
            },
          });
        } catch (errHist) {
          console.error(
            "Erro ao gravar histórico de alteração de status (PUT /solicitacoes/:id):",
            errHist
          );
        }
      }
    }

    res.json(atualizado);
  } catch (err) {
    console.error("Erro em PUT /solicitacoes/:id:", err);
    res.status(500).json({ erro: "Erro ao atualizar solicitação." });
  }
});

// Excluir solicitação
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

    if (prisma.solicitacaoArquivo?.deleteMany) {
      try {
        await prisma.solicitacaoArquivo.deleteMany({
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
    {
      const Historico = getHistoricoModel();
      if (Historico) {
        try {
          await Historico.deleteMany({
            where: { solicitacao_id: solicitacaoId },
          });
        } catch (e) {
          console.error(
            "Erro ao apagar histórico de status da solicitação (ignorando e prosseguindo):",
            e
          );
        }
      }
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
// 🔰 UPLOAD & DOWNLOAD DE ARQUIVOS
// =========================

// Upload de arquivos vinculados à solicitação
app.post(
  "/solicitacoes/:id/arquivos",
  authMiddleware,
  upload.array("arquivos", 10),
  async (req, res) => {
    try {
      const solicitacaoId = Number(req.params.id);

      const solicitacao = await prisma.solicitacao.findUnique({
        where: { id: solicitacaoId },
      });

      if (!solicitacao) {
        return res.status(404).json({ erro: "Solicitação não encontrada." });
      }

      if (
        req.user.tipo !== "admin" &&
        solicitacao.usuario_id !== req.user.id
      ) {
        return res.status(403).json({
          erro: "Usuário não autorizado a enviar arquivos para esta solicitação.",
        });
      }

      const arquivosSub = req.files || [];

      const ArquivosModel = getArquivosModel();
      if (!ArquivosModel) {
        return res.status(500).json({
          erro: "Modelo de anexos não configurado no servidor.",
        });
      }

      const registros = [];
      for (const file of arquivosSub) {
        const registro = await ArquivosModel.create({
          data: {
            solicitacao_id: solicitacaoId,
            nome_original: file.originalname,
            path: file.filename,
            tamanho_bytes: file.size,
            mime_type: file.mimetype,
          },
        });
        registros.push(registro);
      }

      res.json({
        mensagem: "Arquivos enviados com sucesso.",
        arquivos: registros,
      });
    } catch (err) {
      console.error(
        "Erro em POST /solicitacoes/:id/arquivos:",
        err
      );
      res.status(500).json({ erro: "Erro ao enviar arquivos." });
    }
  }
);

// Listar arquivos de uma solicitação
app.get(
  "/solicitacoes/:id/arquivos",
  authMiddleware,
  async (req, res) => {
    try {
      const solicitacaoId = Number(req.params.id);

      const solicitacao = await prisma.solicitacao.findUnique({
        where: { id: solicitacaoId },
      });

      if (!solicitacao) {
        return res.status(404).json({ erro: "Solicitação não encontrada." });
      }

      if (
        req.user.tipo !== "admin" &&
        solicitacao.usuario_id !== req.user.id
      ) {
        return res.status(403).json({
          erro: "Usuário não autorizado a ver arquivos desta solicitação.",
        });
      }

      const ArquivosModel = getArquivosModel();
      if (!ArquivosModel) {
        return res.json([]);
      }

      const arquivos = await ArquivosModel.findMany({
        where: { solicitacao_id: solicitacaoId },
        orderBy: { id: "asc" },
      });

      res.json(arquivos);
    } catch (err) {
      console.error(
        "Erro em GET /solicitacoes/:id/arquivos:",
        err
      );
      res.status(500).json({ erro: "Erro ao buscar arquivos." });
    }
  }
);

// Baixar arquivo específico
app.get(
  "/arquivos/:id/download",
  authMiddleware,
  async (req, res) => {
    try {
      const arquivoId = Number(req.params.id);

      const ArquivosModel = getArquivosModel();
      if (!ArquivosModel) {
        return res.status(404).json({ erro: "Modelo de anexos não encontrado." });
      }

      const arquivo = await ArquivosModel.findUnique({
        where: { id: arquivoId },
        include: { solicitacao: true },
      });

      if (!arquivo) {
        return res.status(404).json({ erro: "Arquivo não encontrado." });
      }

      if (
        req.user.tipo !== "admin" &&
        arquivo.solicitacao.usuario_id !== req.user.id
      ) {
        return res.status(403).json({
          erro: "Usuário não autorizado a baixar este arquivo.",
        });
      }

      const fullPath = path.join(uploadDir, arquivo.path);

      if (!fs.existsSync(fullPath)) {
        return res.status(404).json({
          erro: "Arquivo físico não encontrado no servidor.",
        });
      }

      res.download(fullPath, arquivo.nome_original || "arquivo");
    } catch (err) {
      console.error("Erro em GET /arquivos/:id/download:", err);
      res.status(500).json({ erro: "Erro ao baixar arquivo." });
    }
  }
);

// Deletar arquivo específico
app.delete(
  "/arquivos/:id",
  authMiddleware,
  async (req, res) => {
    try {
      const arquivoId = Number(req.params.id);

      const ArquivosModel = getArquivosModel();
      if (!ArquivosModel) {
        return res.status(404).json({ erro: "Modelo de anexos não encontrado." });
      }

      const arquivo = await ArquivosModel.findUnique({
        where: { id: arquivoId },
        include: { solicitacao: true },
      });

      if (!arquivo) {
        return res.status(404).json({ erro: "Arquivo não encontrado." });
      }

      if (
        req.user.tipo !== "admin" &&
        arquivo.solicitacao.usuario_id !== req.user.id
      ) {
        return res.status(403).json({
          erro: "Usuário não autorizado a excluir este arquivo.",
        });
      }

      const fullPath = path.join(uploadDir, arquivo.path);

      try {
        if (fs.existsSync(fullPath)) {
          fs.unlinkSync(fullPath);
        }
      } catch (e) {
        console.error(
          `Erro ao remover arquivo físico (id=${arquivo.id}, path=${arquivo.path}):`,
          e
        );
      }

      await ArquivosModel.delete({
        where: { id: arquivoId },
      });

      res.json({ ok: true });
    } catch (err) {
      console.error("Erro em DELETE /arquivos/:id:", err);
      res.status(500).json({ erro: "Erro ao excluir arquivo." });
    }
  }
);

// =========================
// 🔰 HISTÓRICO POR SOLICITAÇÃO
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

    const Historico = getHistoricoModel();
    if (!Historico) {
      return res.json([]);
    }

    const lista = await Historico.findMany({
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

    // Se o status for "Aguardando documento", 'obs' é obrigatória
    if (status === "Aguardando documento") {
      if (!obs || String(obs).trim() === "") {
        return res.status(400).json({
          erro: "Campo 'obs' é obrigatório quando o status é 'Aguardando documento'.",
        });
      }
    }

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

    {
      const Historico = getHistoricoModel();
      if (Historico) {
        const dataHistorico =
          req.body.data ||
          req.body.data_solicitacao ||
          new Date();

        await Historico.create({
          data: {
            solicitacao_id: Number(id),
            status,
            data: dataHistorico,
            origem: origem || "Sistema",
            obs: obs || null,
          },
        });
      }
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
    const solicitacoes = await prisma.solicitacao.findMany({
      orderBy: { criado_em: "asc" },
      include: {
        usuario: true,
        descricao: true,
      },
    });

    const colunas = {};

    for (const sol of solicitacoes) {
      const statusColuna = sol.status || "Sem status";
      if (!colunas[statusColuna]) {
        colunas[statusColuna] = [];
      }

      colunas[statusColuna].push({
        id: sol.id,
        usuario_id: sol.usuario_id,
        solicitante_nome: sol.usuario?.nome || null,
        descricao_id: sol.descricao_id,
        descricao_nome: sol.descricao?.descricao || null,
        numero_nf: sol.numero_nf,
        data_nf: sol.data_nf,
        valor_nf: sol.valor_nf,
        emitente_nome: sol.emitente_nome,
        emitente_doc: sol.emitente_doc,
        beneficiario_nome: sol.beneficiario_nome,
        beneficiario_doc: sol.beneficiario_doc,
        status: sol.status,
        data_solicitacao: sol.data_solicitacao,
        criado_em: sol.criado_em,
        atualizado_em: sol.atualizado_em,
      });
    }

    res.json(colunas);
  } catch (err) {
    console.error("Erro em GET /kanban:", err);
    res.status(500).json({ erro: "Erro ao carregar kanban." });
  }
});

// =========================
// 🔰 DASHBOARD (ADMIN)
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

    const ultimas = ultimasRaw.map((sol) => ({
      id: sol.id,
      usuario_id: sol.usuario_id,
      solicitante_nome: sol.usuario?.nome || null,
      solicitante_email: sol.usuario?.email || null,
      descricao_id: sol.descricao_id,
      descricao_nome: sol.descricao?.descricao || null,
      numero_nf: sol.numero_nf,
      data_nf: sol.data_nf,
      valor_nf: sol.valor_nf,
      emitente_nome: sol.emitente_nome,
      emitente_doc: sol.emitente_doc,
      beneficiario_nome: sol.beneficiario_nome,
      beneficiario_doc: sol.beneficiario_doc,
      status: sol.status,
      data_solicitacao: sol.data_solicitacao,
      criado_em: sol.criado_em,
      atualizado_em: sol.atualizado_em,
      arquivos: sol.arquivos || [],
    }));

    res.json({
      totalSolicitacoes,
      totaisPorStatus,
      ultimas,
    });
  } catch (err) {
    console.error("Erro em GET /dashboard:", err);
    res.status(500).json({ erro: "Erro ao carregar dashboard." });
  }
});

// =========================
// 🔰 HISTÓRICO GLOBAL
// =========================
app.get("/historico", authMiddleware, adminOnly, async (req, res) => {
  try {
    const Historico = getHistoricoModel();
    if (!Historico) {
      return res.json([]);
    }

    const lista = await Historico.findMany({
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
    const solicitacoes = await prisma.solicitacao.findMany({
      orderBy: { data_nf: "asc" },
    });

    const linhas = solicitacoes.map((s) => {
      const dataNF = s.data_nf
        ? new Date(s.data_nf).toISOString().slice(0, 10)
        : "";

      const valor = s.valor_nf != null ? s.valor_nf.toFixed(2) : "";

      return [
        s.id,
        s.numero_nf || "",
        dataNF,
        valor,
        s.emitente_nome || "",
        s.emitente_doc || "",
        s.beneficiario_nome || "",
        s.beneficiario_doc || "",
        s.status || "",
      ].join(";");
    });

    const cabecalho = [
      "ID",
      "Numero NF",
      "Data NF",
      "Valor NF",
      "Emitente Nome",
      "Emitente Doc",
      "Beneficiario Nome",
      "Beneficiario Doc",
      "Status",
    ].join(";");

    const conteudo = [cabecalho, ...linhas].join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="relatorio_irpf.csv"'
    );

    res.send(conteudo);
  } catch (err) {
    console.error("Erro em GET /relatorios/irpf:", err);
    res.status(500).json({ erro: "Erro ao gerar relatório IRPF." });
  }
});

// =========================
// 🔰 CONFIGURAÇÕES / DEBUG DO BANCO
// =========================

// Listar estrutura básica do banco (tabelas principais)
app.get("/config/estrutura-banco", authMiddleware, adminOnly, async (req, res) => {
  try {
    const tabelas = [
      "usuario",
      "descricao",
      "status",
      "solicitacao",
      "SolicitacaoStatusHistory (tabela solicitacao_status_history)",
    ];

    res.json({
      banco: process.env.DATABASE_URL || "N/D",
      tabelas,
    });
  } catch (err) {
    console.error("Erro em GET /config/estrutura-banco:", err);
    res.status(500).json({ erro: "Erro ao obter estrutura do banco." });
  }
});

// =========================
// 🔰 INICIALIZAÇÃO DO SERVIDOR
// =========================
app.listen(PORT, () => {
  console.log(`API Reembolso rodando na porta ${PORT}.`);
});
