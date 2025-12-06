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

// =========================
// 🔰 MIDDLEWARES BÁSICOS
// =========================
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:4173",
      "https://controle-de-reembolso.vercel.app",
    ],
    credentials: true,
  })
);

app.use(express.json());

// =========================
// 🔰 HELPERS GERAIS
// =========================
function normalizarNumero(valor) {
  if (valor === null || valor === undefined || valor === "") return null;

  if (typeof valor === "number") return valor;

  if (typeof valor === "string") {
    const limpo = valor.replace(/\./g, "").replace(",", ".");
    const num = Number(limpo);
    return Number.isNaN(num) ? null : num;
  }

  return null;
}

function normalizarData(valor) {
  if (!valor) return null;

  if (valor instanceof Date && !isNaN(valor)) return valor;

  if (typeof valor === "string") {
    const v = valor.trim();
    if (!v) return null;

    if (/^\d{2}\/\d{2}\/\d{4}$/.test(v)) {
      const [dia, mes, ano] = v.split("/");
      const dt = new Date(Number(ano), Number(mes) - 1, Number(dia));
      if (!isNaN(dt)) return dt;
      return null;
    }

    const dtISO = new Date(v);
    if (!isNaN(dtISO)) return dtISO;
  }

  return null;
}

function gerarToken(usuario) {
  const payload = {
    id: usuario.id,
    email: usuario.email,
    tipo: usuario.tipo,
    nome: usuario.nome,
  };

  const secret = process.env.JWT_SECRET || "segredo_super_secreto";

  return jwt.sign(payload, secret, { expiresIn: "8h" });
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const [, token] = authHeader.split(" ");

  if (!token) {
    return res.status(401).json({ erro: "Token não fornecido." });
  }

  try {
    const secret = process.env.JWT_SECRET || "segredo_super_secreto";
    const decoded = jwt.verify(token, secret);
    req.user = decoded;
    next();
  } catch (err) {
    console.error("Erro ao validar token:", err);
    return res.status(401).json({ erro: "Token inválido ou expirado." });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.tipo !== "admin") {
    return res.status(403).json({ erro: "Acesso restrito a administradores." });
  }
  next();
}

// =========================
// 🔰 MODELOS AUXILIARES
// =========================
const arquivosModel =
  prisma.solicitacaoArquivo ||
  prisma.solicitacaoArquivos ||
  prisma.arquivo ||
  prisma.arquivos ||
  null;

function getHistoricoModel() {
  const Historico = prisma.solicitacaoStatusHistory;

  if (!Historico) {
    console.error(
      "Modelo SolicitacaoStatusHistory (tabela solicitacao_status_history) não encontrado no Prisma Client."
    );
  }

  return Historico;
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
    console.error("Erro em /health:", err);
    res.status(500).json({ status: "error", detalhe: String(err) });
  }
});

// =========================
// 🔰 LOGIN & AUTENTICAÇÃO
// =========================
app.post("/auth/login", async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res
        .status(400)
        .json({ erro: "E-mail e senha são obrigatórios." });
    }

    const usuario = await prisma.usuarios.findUnique({
      where: { email },
    });

    if (!usuario) {
      return res.status(401).json({ erro: "Usuário não encontrado." });
    }

    const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
    if (!senhaValida) {
      return res.status(401).json({ erro: "Usuário ou senha inválidos." });
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

app.post("/auth/reset-solicitar", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !String(email).trim()) {
      return res.status(400).json({ erro: "E-mail é obrigatório." });
    }

    const usuario = await prisma.usuarios.findUnique({
      where: { email },
    });

    if (!usuario) {
      return res
        .status(404)
        .json({ erro: "Usuário com esse e-mail não foi encontrado." });
    }

    const secret = process.env.JWT_SECRET || "segredo_super_secreto";
    const token = jwt.sign({ id: usuario.id }, secret, { expiresIn: "1h" });

    const resetLink = `${
      process.env.APP_BASE_URL || "https://controle-de-reembolso.vercel.app"
    }/resetar-senha?token=${token}`;

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT || 587,
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

app.post("/auth/esqueci-senha", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !String(email).trim()) {
      return res.status(400).json({ erro: "E-mail é obrigatório." });
    }

    const usuario = await prisma.usuarios.findUnique({
      where: { email },
    });

    if (!usuario) {
      return res
        .status(404)
        .json({ erro: "Usuário com esse e-mail não foi encontrado." });
    }

    const secret = process.env.JWT_SECRET || "segredo_super_secreto";
    const token = jwt.sign({ id: usuario.id }, secret, { expiresIn: "1h" });

    const resetLink = `${
      process.env.APP_BASE_URL || "https://controle-de-reembolso.vercel.app"
    }/resetar-senha?token=${token}`;

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT || 587,
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
    res.status(500).json({ erro: "Erro ao solicitar redefinição de senha." });
  }
});

app.post("/auth/resetar-senha", async (req, res) => {
  try {
    const { token, novaSenha } = req.body;

    if (!token || !novaSenha) {
      return res
        .status(400)
        .json({ erro: "Token e nova senha são obrigatórios." });
    }

    const secret = process.env.JWT_SECRET || "segredo_super_secreto";
    let payload;
    try {
      payload = jwt.verify(token, secret);
    } catch (err) {
      return res.status(400).json({ erro: "Token inválido ou expirado." });
    }

    const usuario = await prisma.usuarios.findUnique({
      where: { id: payload.id },
    });

    if (!usuario) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    const hash = await bcrypt.hash(novaSenha, 10);

    await prisma.usuarios.update({
      where: { id: usuario.id },
      data: { senha_hash: hash },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erro em /auth/resetar-senha:", err);
    res.status(500).json({ erro: "Erro ao redefinir senha." });
  }
});

// =========================
// 🔰 USUÁRIOS
// =========================
app.get("/usuarios", authMiddleware, adminOnly, async (req, res) => {
  try {
    const usuarios = await prisma.usuarios.findMany({
      orderBy: { id: "asc" },
    });
    res.json(usuarios);
  } catch (err) {
    console.error("Erro em GET /usuarios:", err);
    res.status(500).json({ erro: "Erro ao listar usuários." });
  }
});

app.get("/usuarios/me", authMiddleware, async (req, res) => {
  try {
    const usuario = await prisma.usuarios.findUnique({
      where: { id: req.user.id },
    });

    if (!usuario) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    res.json({
      id: usuario.id,
      nome: usuario.nome,
      email: usuario.email,
      cpf: usuario.cpf,
      telefone: usuario.telefone,
      tipo: usuario.tipo,
      ativo: usuario.ativo,
      criado_em: usuario.criado_em,
      atualizado_em: usuario.atualizado_em,
    });
  } catch (err) {
    console.error("Erro em GET /usuarios/me:", err);
    res.status(500).json({ erro: "Erro ao buscar dados do usuário." });
  }
});

app.put("/usuarios/me", authMiddleware, async (req, res) => {
  try {
    const { nome, telefone } = req.body;

    const atualizado = await prisma.usuarios.update({
      where: { id: req.user.id },
      data: {
        nome: nome ?? undefined,
        telefone: telefone ?? undefined,
      },
    });

    res.json({
      id: atualizado.id,
      nome: atualizado.nome,
      email: atualizado.email,
      cpf: atualizado.cpf,
      telefone: atualizado.telefone,
      tipo: atualizado.tipo,
      ativo: atualizado.ativo,
      criado_em: atualizado.criado_em,
      atualizado_em: atualizado.atualizado_em,
    });
  } catch (err) {
    console.error("Erro em PUT /usuarios/me:", err);
    res.status(500).json({ erro: "Erro ao atualizar dados do usuário." });
  }
});

app.post("/usuarios", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { nome, email, senha, tipo, cpf, telefone, ativo } = req.body;

    if (!nome || !email || !senha) {
      return res
        .status(400)
        .json({ erro: "Nome, e-mail e senha são obrigatórios." });
    }

    const existente = await prisma.usuarios.findUnique({
      where: { email },
    });

    if (existente) {
      return res.status(400).json({ erro: "E-mail já cadastrado." });
    }

    const hash = await bcrypt.hash(senha, 10);

    const criado = await prisma.usuarios.create({
      data: {
        nome,
        email,
        senha_hash: hash,
        tipo: tipo || "usuario",
        cpf: cpf || null,
        telefone: telefone || null,
        ativo: ativo !== undefined ? !!ativo : true,
      },
    });

    res.json({
      id: criado.id,
      nome: criado.nome,
      email: criado.email,
      cpf: criado.cpf,
      telefone: criado.telefone,
      tipo: criado.tipo,
      ativo: criado.ativo,
      criado_em: criado.criado_em,
      atualizado_em: criado.atualizado_em,
    });
  } catch (err) {
    console.error("Erro em POST /usuarios:", err);
    res.status(500).json({ erro: "Erro ao criar usuário." });
  }
});

app.put("/usuarios/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { nome, email, senha, tipo, cpf, telefone, ativo } = req.body;

    const dadosAtualizar = {
      nome: nome ?? undefined,
      email: email ?? undefined,
      tipo: tipo ?? undefined,
      cpf: cpf ?? undefined,
      telefone: telefone ?? undefined,
      ativo: ativo !== undefined ? !!ativo : undefined,
    };

    if (senha) {
      dadosAtualizar.senha_hash = await bcrypt.hash(senha, 10);
    }

    const atualizado = await prisma.usuarios.update({
      where: { id: Number(id) },
      data: dadosAtualizar,
    });

    res.json({
      id: atualizado.id,
      nome: atualizado.nome,
      email: atualizado.email,
      cpf: atualizado.cpf,
      telefone: atualizado.telefone,
      tipo: atualizado.tipo,
      ativo: atualizado.ativo,
      criado_em: atualizado.criado_em,
      atualizado_em: atualizado.atualizado_em,
    });
  } catch (err) {
    console.error("Erro em PUT /usuarios/:id:", err);
    res.status(500).json({ erro: "Erro ao atualizar usuário." });
  }
});

app.delete("/usuarios/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.usuarios.delete({
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
        .json({ erro: "Descrição é obrigatória." });
    }

    const criada = await prisma.descricoes.create({
      data: {
        descricao,
        ativo: ativo !== undefined ? !!ativo : true,
      },
    });

    res.json(criada);
  } catch (err) {
    console.error("Erro em POST /descricoes:", err);
    res.status(500).json({ erro: "Erro ao criar descrição." });
  }
});

app.put("/descricoes/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { descricao, ativo } = req.body;

    const atualizada = await prisma.descricoes.update({
      where: { id: Number(id) },
      data: {
        descricao: descricao ?? undefined,
        ativo: ativo !== undefined ? !!ativo : undefined,
      },
    });

    res.json(atualizada);
  } catch (err) {
    console.error("Erro em PUT /descricoes/:id:", err);
    res.status(500).json({ erro: "Erro ao atualizar descrição." });
  }
});

app.delete("/descricoes/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.descricoes.delete({
      where: { id: Number(id) },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erro em DELETE /descricoes/:id:", err);
    res.status(500).json({ erro: "Erro ao excluir descrição." });
  }
});

// =========================
// 🔰 STATUS
// =========================
app.get("/status", async (req, res) => {
  try {
    const lista = await prisma.status.findMany({
      where: { ativo: true },
      orderBy: { id: "asc" },
    });
    res.json(lista);
  } catch (err) {
    console.error("Erro em GET /status:", err);
    res.status(500).json({ erro: "Erro ao listar status." });
  }
});

app.post("/status", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { nome, ativo } = req.body;

    if (!nome || !String(nome).trim()) {
      return res.status(400).json({ erro: "Nome do status é obrigatório." });
    }

    const criado = await prisma.status.create({
      data: {
        nome,
        ativo: ativo !== undefined ? !!ativo : true,
      },
    });

    res.json(criado);
  } catch (err) {
    console.error("Erro em POST /status:", err);
    res.status(500).json({ erro: "Erro ao criar status." });
  }
});

app.put("/status/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { nome, ativo } = req.body;

    const atualizado = await prisma.status.update({
      where: { id: Number(id) },
      data: {
        nome: nome ?? undefined,
        ativo: ativo !== undefined ? !!ativo : undefined,
      },
    });

    res.json(atualizado);
  } catch (err) {
    console.error("Erro em PUT /status/:id:", err);
    res.status(500).json({ erro: "Erro ao atualizar status." });
  }
});

app.delete("/status/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.status.delete({
      where: { id: Number(id) },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erro em DELETE /status/:id:", err);
    res.status(500).json({ erro: "Erro ao excluir status." });
  }
});

// =========================
// 🔰 SOLICITAÇÕES — LISTAGEM
// =========================
function mapSolicitacaoComSolicitante(s) {
  const nomeSolicitante =
    (s.usuario && s.usuario.nome) ||
    s.solicitante_nome ||
    s.solicitante ||
    "";

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

app.get("/solicitacoes", authMiddleware, async (req, res) => {
  try {
    let where = {};
    if (req.user.tipo !== "admin") {
      where.usuario_id = req.user.id;
    }

    const solicitacoes = await prisma.solicitacao.findMany({
      where,
      orderBy: { id: "desc" },
      include: {
        usuario: true,
        anexos: true,
      },
    });

    const mapped = solicitacoes.map(mapSolicitacaoComSolicitante);

    res.json(mapped);
  } catch (err) {
    console.error("Erro em GET /solicitacoes:", err);
    res.status(500).json({ erro: "Erro ao listar solicitações." });
  }
});

// =========================
// 🔰 SOLICITAÇÕES — CRIAÇÃO
// =========================
app.post("/solicitacoes", authMiddleware, async (req, res) => {
  try {
    const dados = req.body;
    const usuarioId = dados.usuario_id || req.user.id;

    const dataCriar = {
      usuario_id: usuarioId,
      solicitante_nome: dados.solicitante_nome || dados.solicitante || null,
      beneficiario_nome: dados.beneficiario_nome || null,
      beneficiario_doc: dados.beneficiario_doc || null,
      numero_nf: dados.numero_nf || null,
      data_nf: normalizarData(dados.data_nf) || null,
      data_solicitacao:
        normalizarData(dados.data_solicitacao) ||
        normalizarData(dados.data) ||
        new Date(),
      valor_nf: normalizarNumero(dados.valor_nf),
      emitente_nome: dados.emitente_nome || null,
      emitente_doc: dados.emitente_doc || null,
      descricao_id: dados.descricao_id || null,
      status: dados.status || "Em análise",
      observacao: dados.observacao || null,
    };

    if (!dataCriar.status) {
      dataCriar.status = dados.status || "Em análise";
    }

    const nova = await prisma.solicitacao.create({
      data: dataCriar,
    });

    const dataHistorico =
      normalizarData(dados.data) ||
      normalizarData(dados.data_solicitacao) ||
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
        console.error("Erro ao gravar histórico inicial da solicitação:", errHist);
      }
    }

    res.json(nova);
  } catch (err) {
    console.error("Erro em POST /solicitacoes:", err);
    res.status(500).json({ erro: "Erro ao criar solicitação." });
  }
});

// =========================
// 🔰 SOLICITAÇÕES — UPLOAD ARQUIVOS
// =========================
app.post(
  "/solicitacoes/:id/arquivos",
  authMiddleware,
  upload.array("arquivos"),
  async (req, res) => {
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
          erro: "Usuário não autorizado a enviar arquivos para esta solicitação.",
        });
      }

      if (!arquivosModel) {
        return res.status(500).json({
          erro: "Modelo de arquivos não configurado no Prisma.",
        });
      }

      const arquivosSalvos = [];

      for (const file of req.files) {
        const registro = await arquivosModel.create({
          data: {
            solicitacao_id: solicitacaoId,
            caminho: file.filename,
            nome_original: file.originalname,
            mime_type: file.mimetype,
            tamanho: file.size,
          },
        });

        arquivosSalvos.push(registro);
      }

      res.json(arquivosSalvos);
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
// 🔰 SOLICITAÇÕES — UPDATE
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

    const statusAntes = existente.status;

    if (req.user.tipo !== "admin" && existente.usuario_id !== req.user.id) {
      return res.status(403).json({
        erro: "Usuário não autorizado a alterar esta solicitação.",
      });
    }

    const camposPermitidos = [
      "solicitante_nome",
      "beneficiario_nome",
      "beneficiario_doc",
      "numero_nf",
      "data_nf",
      "data_solicitacao",
      "valor_nf",
      "emitente_nome",
      "emitente_doc",
      "descricao_id",
      "status",
      "observacao",
      "usuario_id",
    ];

    const camposNumericos = ["valor_nf"];
    const camposData = ["data_nf", "data_solicitacao"];

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
          const obsHistorico =
            dados.obs ??
            dados.observacao ??
            null;

          // ✅ DATA DO MOVIMENTO (EDIÇÃO): usa preferencialmente a data enviada pelo modal (dados.data)
          const dataHistorico =
            normalizarData(dados.data) ||
            atualizado.data_ultima_mudanca ||
            new Date();

          await Historico.create({
            data: {
              solicitacao_id: solicitacaoId,
              status: atualizado.status,
              data: dataHistorico,
              origem: "Edição",
              obs: obsHistorico,
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

// =========================
// 🔰 SOLICITAÇÕES — DELETE
// =========================
app.delete("/solicitacoes/:id", authMiddleware, async (req, res) => {
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
        erro: "Usuário não autorizado a excluir esta solicitação.",
      });
    }

    await prisma.solicitacao.delete({
      where: { id: solicitacaoId },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erro em DELETE /solicitacoes/:id:", err);
    res.status(500).json({ erro: "Erro ao excluir solicitação." });
  }
});

// =========================
// 🔰 SOLICITAÇÕES — HISTÓRICO (POR SOLICITAÇÃO)
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
// 🔰 SOLICITAÇÕES — HISTÓRICO GLOBAL
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
// 🔰 ALTERAÇÃO DE STATUS ESPECÍFICA (KANBAN)
// =========================
app.put("/solicitacoes/:id/status", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, origem, obs } = req.body;

    // Se o status for "Aguardando documento", obs é obrigatória
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

    const Historico = getHistoricoModel();
    if (Historico) {
      const dataHistorico =
        normalizarData(req.body.data) ||
        atualizado.data_ultima_mudanca ||
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

    res.json({ ok: true, atualizado });
  } catch (err) {
    console.error("Erro em PUT /solicitacoes/:id/status:", err);
    res.status(500).json({ erro: "Erro ao atualizar status." });
  }
});

// =========================
// 🔰 DASHBOARD
// =========================
app.get("/dashboard", authMiddleware, async (req, res) => {
  try {
    let where = {};
    if (req.user.tipo !== "admin") {
      where.usuario_id = req.user.id;
    }

    const totalSolicitacoes = await prisma.solicitacao.count({ where });

    const agrupadoStatus = await prisma.solicitacao.groupBy({
      by: ["status"],
      where,
      _count: { _all: true },
    });

    const totalPorStatus = {};
    for (const item of agrupadoStatus) {
      totalPorStatus[item.status] = item._count._all;
    }

    const somaValores = await prisma.solicitacao.aggregate({
      where,
      _sum: { valor_nf: true },
    });

    res.json({
      totalSolicitacoes,
      totalPorStatus,
      valorTotal: somaValores._sum.valor_nf || 0,
    });
  } catch (err) {
    console.error("Erro em GET /dashboard:", err);
    res.status(500).json({ erro: "Erro ao buscar dados do dashboard." });
  }
});

// =========================
// 🔰 RELATÓRIOS — IMPORTAÇÃO IRPF
// =========================
app.get("/relatorios/irpf", authMiddleware, async (req, res) => {
  try {
    let where = {};
    if (req.user.tipo !== "admin") {
      where.usuario_id = req.user.id;
    }

    const solicitacoes = await prisma.solicitacao.findMany({
      where,
      orderBy: { data_nf: "asc" },
    });

    res.json(solicitacoes);
  } catch (err) {
    console.error("Erro em GET /relatorios/irpf:", err);
    res.status(500).json({ erro: "Erro ao gerar relatório IRPF." });
  }
});

// =========================
// 🔰 CONFIGURAÇÕES — GERA ESTRUTURA DO BANCO
// =========================
app.get("/config/estrutura-banco", authMiddleware, adminOnly, async (req, res) => {
  try {
    const result = await prisma.$queryRawUnsafe(`
      SELECT table_name, column_name, data_type
      FROM information_schema.columns
      WHERE table_schema = 'public'
      ORDER BY table_name, ordinal_position;
    `);

    let texto = "";
    let tabelaAtual = "";
    for (const row of result) {
      if (row.table_name !== tabelaAtual) {
        tabelaAtual = row.table_name;
        texto += `\nTabela: ${tabelaAtual}\n`;
      }
      texto += `  - ${row.column_name}: ${row.data_type}\n`;
    }

    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send(texto);
  } catch (err) {
    console.error("Erro em GET /config/estrutura-banco:", err);
    res.status(500).json({ erro: "Não foi possível gerar a estrutura do banco." });
  }
});

// =========================
// 🔰 STATIC (UPLOADS)
// =========================
app.use("/uploads", express.static(uploadDir));

// =========================
// 🔰 START SERVER
// =========================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`API Reembolso rodando na porta ${PORT}`);
});
