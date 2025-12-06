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
  prisma.solicitacaoArquivo || // ex: model Solicitacao_arquivos
  prisma.solicitacaoArquivos || // ex: model SolicitacaoArquivos
  prisma.arquivo || // ex: model Arquivo
  prisma.arquivos || // ex: model Arquivos
  null;

function getArquivosModel() {
  if (!arquivosModel) {
    console.error(
      "Modelo de anexos (solicitacao_arquivos / solicitacaoArquivos / arquivo) não encontrado no Prisma Client."
    );
  }
  return arquivosModel;
}

// Helper para acessar o modelo de histórico de status (model SolicitacaoStatusHistory → tabela solicitacao_status_history)
function getHistoricoModel() {
  const Historico = prisma.solicitacaoStatusHistory; // nome exato do model no Prisma

  if (!Historico) {
    console.error(
      "Modelo SolicitacaoStatusHistory (tabela solicitacao_status_history) não encontrado no Prisma Client."
    );
  }

  return Historico;
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

      if (
        origin.endsWith(".vercel.app") &&
        origin.includes("controle-de-reembolso")
      ) {
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
    return res
      .status(403)
      .json({ erro: "Acesso restrito a administradores." });
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
      return res.status(400).json({
        ok: false,
        success: false,
        status: "error",
        mensagem: "Usuário não encontrado.",
      });
    }

    const senhaOk = await bcrypt.compare(senha, usuario.senha_hash);
    if (!senhaOk) {
      return res.status(400).json({
        ok: false,
        success: false,
        status: "error",
        mensagem: "Usuário ou senha inválidos.",
      });
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
    res.status(500).json({
      ok: false,
      success: false,
      status: "error",
      mensagem: "Erro interno ao tentar fazer login.",
    });
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
      return res
        .status(400)
        .json({ ok: false, mensagem: "E-mail é obrigatório." });
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

    if (
      process.env.SMTP_HOST &&
      process.env.SMTP_USER &&
      process.env.SMTP_PASS
    ) {
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
      return res
        .status(400)
        .json({ erro: "Token e nova senha são obrigatórios." });
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
  const nomeSolicitante =
    s.usuario?.nome || s.solicitante_nome || s.solicitante || "";

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

/**
 * Anexa o histórico de status (tabela solicitacao_status_history)
 * a cada solicitação, preenchendo o campo `statusHistory`.
 */
async function attachHistoricoToSolicitacoes(solicitacoesRaw) {
  const Historico = getHistoricoModel();

  if (!Array.isArray(solicitacoesRaw) || solicitacoesRaw.length === 0) {
    return [];
  }

  // Se não tiver model de histórico, devolve só com o mapeamento padrão
  if (!Historico) {
    return solicitacoesRaw.map((s) => ({
      ...mapSolicitacaoComSolicitante(s),
      statusHistory: [],
    }));
  }

  const ids = solicitacoesRaw.map((s) => s.id);
  const historicos = await Historico.findMany({
    where: {
      solicitacao_id: { in: ids },
    },
    orderBy: { data: "asc" }, // cronológico (mais antigo → mais recente)
  });

  const porSolic = {};
  for (const h of historicos) {
    if (!porSolic[h.solicitacao_id]) porSolic[h.solicitacao_id] = [];
    porSolic[h.solicitacao_id].push(h);
  }

  return solicitacoesRaw.map((s) => {
    const base = mapSolicitacaoComSolicitante(s);
    const histRows = porSolic[s.id] || [];

    const statusHistory = histRows.map((h) => ({
      id: h.id,
      status: h.status,
      date:
        h.data instanceof Date
          ? h.data.toISOString().slice(0, 10)
          : h.data,
      origem: h.origem,
      obs: h.obs,
    }));

    return {
      ...base,
      statusHistory,
    };
  });
}

// =========================
// 🔰 USUÁRIOS — CRUD (Configurações)
// =========================
app.post("/usuarios", authMiddleware, adminOnly, async (req, res) => {
  try {
    const {
      nome,
      email,
      senha,
      tipo,
      ativo,
      cpfcnpj,
      cpfCnpj,
      telefone,
    } = req.body;

    // ✅ Agora só exigimos nome e e-mail
    if (!nome || !email) {
      return res
        .status(400)
        .json({ erro: "Nome e e-mail são obrigatórios." });
    }

    const existente = await prisma.usuario.findFirst({ where: { email } });

    if (existente) {
      return res
        .status(400)
        .json({ erro: "Já existe um usuário cadastrado com esse e-mail." });
    }

    // ✅ Se não vier senha, geramos uma senha temporária
    let senhaFinal =
      (senha && String(senha).trim()) ||
      Math.random().toString(36).slice(-8); // ex: "a9f3x2k1"

    // (opcional) logar no servidor para consulta, se quiser:
    console.log(
      `🔐 Senha temporária gerada para o usuário ${email}: ${senhaFinal}`
    );

    const hash = await bcrypt.hash(senhaFinal, 10);

    const cpfValue = cpfcnpj || cpfCnpj || null;

    const novo = await prisma.usuario.create({
      data: {
        nome: String(nome).trim(),
        email: String(email).trim(),
        senha_hash: hash,
        tipo: tipo || "user",
        ativo: ativo !== undefined ? !!ativo : true,
        cpfcnpj: cpfValue,
        telefone: telefone || null,
        primeiro_acesso: true, // usuário pode ser obrigado a trocar depois, se você quiser tratar no front
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
    const {
      nome,
      email,
      senha,
      tipo,
      ativo,
      cpfcnpj,
      cpfCnpj,
      telefone,
    } = req.body;

    const data = {};

    if (nome !== undefined) data.nome = String(nome).trim();
    if (email !== undefined) data.email = String(email).trim();
    if (tipo !== undefined) data.tipo = tipo;
    if (ativo !== undefined) data.ativo = !!ativo;

    const cpfValue = cpfcnpj ?? cpfCnpj;
    if (cpfValue !== undefined) {
      data.cpfcnpj = cpfValue || null;
    }

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

// PATCH /usuarios/:id — alias do PUT para compatibilidade com o front
app.patch("/usuarios/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      nome,
      email,
      senha,
      tipo,
      ativo,
      cpfcnpj,
      cpfCnpj,
      telefone,
    } = req.body;

    const data = {};

    if (nome !== undefined) data.nome = String(nome).trim();
    if (email !== undefined) data.email = String(email).trim();
    if (tipo !== undefined) data.tipo = tipo;
    if (ativo !== undefined) data.ativo = !!ativo;

    const cpfValue = cpfcnpj ?? cpfCnpj;
    if (cpfValue !== undefined) {
      data.cpfcnpj = cpfValue || null;
    }

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
    console.error("Erro em PATCH /usuarios/:id:", err);
    res.status(500).json({ erro: "Erro ao salvar usuário." });
  }
});

app.delete("/usuarios/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;

    if (req.user && req.user.id === Number(id)) {
      return res.status(400).json({
        erro: "Você não pode excluir o próprio usuário logado.",
      });
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
      VALUES (${String(descricao).trim()}, ${
      ativo !== undefined ? !!ativo : true
    })
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
        descricao = COALESCE(${
          descricao !== undefined ? String(descricao).trim() : null
        }, descricao),
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

// PATCH /descricoes/:id — alias do PUT para compatibilidade com o front
app.patch("/descricoes/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { descricao, ativo } = req.body;

    const [atualizado] = await prisma.$queryRaw`
      UPDATE descricoes
      SET
        descricao = COALESCE(${
          descricao !== undefined ? String(descricao).trim() : null
        }, descricao),
        ativo = COALESCE(${ativo !== undefined ? !!ativo : null}, ativo)
      WHERE id = ${Number(id)}
      RETURNING id, descricao, ativo;
    `;

    if (!atualizado) {
      return res.status(404).json({ erro: "Descrição não encontrada." });
    }

    res.json(atualizado);
  } catch (err) {
    console.error("Erro em PATCH /descricoes/:id:", err);
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

// PATCH /status/:id — alias do PUT para compatibilidade com o front
app.patch("/status/:id", authMiddleware, adminOnly, async (req, res) => {
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
    console.error("Erro em PATCH /status/:id:", err);
    res.status(500).json({ erro: "Erro ao atualizar status." });
  }
});

// =========================
// 🔰 SOLICITAÇÕES — LISTAR POR USUÁRIO
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

    const resposta = await attachHistoricoToSolicitacoes(dados);

    res.json(resposta);
  } catch (err) {
    console.error("Erro em GET /solicitacoes/usuario/:id:", err);
    res.status(500).json({ erro: "Erro ao buscar solicitações." });
  }
});

// =========================
// 🔰 SOLICITAÇÕES — LISTAR TODAS (ADMIN)
// =========================
app.get("/solicitacoes", authMiddleware, adminOnly, async (req, res) => {
  try {
    const registros = await prisma.solicitacao.findMany({
      orderBy: { criado_em: "desc" },
      include: {
        arquivos: true,
        usuario: true,
      },
    });

    const resposta = await attachHistoricoToSolicitacoes(registros);

    res.json(resposta);
  } catch (err) {
    console.error("Erro em GET /solicitacoes:", err);
    res.status(500).json({ erro: "Erro ao listar solicitações." });
  }
});

// =========================
// 🔰 SOLICITAÇÃO — DETALHE (com histórico)
// =========================
app.get("/solicitacoes/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const solicitacaoId = Number(id);

    const existente = await prisma.solicitacao.findUnique({
      where: { id: solicitacaoId },
      include: {
        arquivos: true,
        usuario: true,
      },
    });

    if (!existente) {
      return res.status(404).json({ erro: "Solicitação não encontrada." });
    }

    // Regra de acesso: admin pode tudo; usuário só a própria
    if (
      req.user.tipo !== "admin" &&
      existente.usuario_id !== req.user.id
    ) {
      return res.status(403).json({
        erro: "Usuário não autorizado a visualizar esta solicitação.",
      });
    }

    const [comHistorico] = await attachHistoricoToSolicitacoes([existente]);

    res.json(comHistorico);
  } catch (err) {
    console.error("Erro em GET /solicitacoes/:id:", err);
    res.status(500).json({ erro: "Erro ao buscar solicitação." });
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

const camposData = [
  "data_nf",
  "data_solicitacao",
  "data_ultima_mudanca",
  "data_pagamento",
];

function normalizarData(valor) {
  if (valor === null || valor === undefined || valor === "") return null;
  if (valor instanceof Date) return valor;

  const s = String(valor).trim();

  // 🔹 Formato ISO "YYYY-MM-DD"
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
    const d = new Date(s + "T00:00:00.000Z");
    if (isNaN(d.getTime())) return null;
    return d;
  }

  // 🔹 Formato brasileiro "DD/MM/AAAA"
  const mBR4 = /^(\d{2})\/(\d{2})\/(\d{4})$/;
  const m4 = s.match(mBR4);
  if (m4) {
    const dia = Number(m4[1]);
    const mes = Number(m4[2]) - 1; // 0–11
    const ano = Number(m4[3]);
    const d = new Date(ano, mes, dia);
    if (isNaN(d.getTime())) return null;
    return d;
  }

  // 🔹 Formato brasileiro "DD/MM/AA" (ex: 01/06/25 → 2025-06-01)
  const mBR2 = /^(\d{2})\/(\d{2})\/(\d{2})$/;
  const m2 = s.match(mBR2);
  if (m2) {
    const dia = Number(m2[1]);
    const mes = Number(m2[2]) - 1;
    let ano = Number(m2[3]);
    // assume século 2000 (20–99 → 2000+, 00–19 → 2000 também)
    ano = 2000 + ano;
    const d = new Date(ano, mes, dia);
    if (isNaN(d.getTime())) return null;
    return d;
  }

  // 🔹 Qualquer outro formato que o JS consiga entender
  const d = new Date(s);
  if (isNaN(d.getTime())) return null;
  return d;
}

/**
 * Tenta descobrir a "data da movimentação" vinda do front.
 * Aceita vários nomes de campo, em ordem de prioridade.
 */
function getDataMovimentacaoFromBody(body) {
  if (!body) return null;

  // 🔹 Ordem de prioridade:
  // 1) Campos específicos de movimentação (se um dia o front mandar)
  // 2) statusDate (é o que já vem do front hoje, em Editar e Kanban)
  // 3) data (em alguns pontos o front manda "data" como data exibida)
  // 4) data_solicitacao como último recurso (mas NUNCA data_ultima_mudanca do body)
  const candidatos = [
    body.data_movimentacao,
    body.dataMovimentacao,
    body.statusDate,
    body.data,
    body.data_solicitacao,
  ];

  for (const v of candidatos) {
    const dt = normalizarData(v);
    if (dt) return dt;
  }

  return null;
}

/**
 * Tenta descobrir o campo de observação/motivo vindo do front.
 * Aceita vários nomes de campo.
 */

function getObsFromBody(body, { permitirDescricao = false } = {}) {
  if (!body) return null;

  const camposBase = [
    "obs",
    "observacao",
    "motivo",
    "motivoObs",
    "motivo_observacao",
  ];

  const campos = permitirDescricao
    ? [...camposBase, "descricao"]
    : camposBase;

  for (const c of campos) {
    if (body[c] !== undefined && body[c] !== null) {
      const txt = String(body[c]).trim();
      if (txt) return txt;
    }
  }

  return null;
}

// =========================
// 🔰 SOLICITAÇÕES — CRIAR
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

    const dataHistorico =
      getDataMovimentacaoFromBody(dados) ||
      dataCriar.data_solicitacao ||
      normalizarData(dados.data_solicitacao) ||
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
            obs: getObsFromBody(dados, { permitirDescricao: true }),
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

// =========================
// 🔰 SOLICITAÇÕES — ATUALIZAR (Editar)
// =========================
app.put("/solicitacoes/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const dados = req.body;
    const solicitacaoId = Number(id);

    const existente = await prisma.solicitacao.findUnique({
      where: { id: solicitacaoId },
    });

    console.log("=== DEBUG EDITAR SOLICITACAO ===");
    console.log("ID:", solicitacaoId);
    console.log("Body recebido (req.body):", JSON.stringify(dados, null, 2));
    console.log("Solicitação existente:", {
      id: existente?.id,
      status: existente?.status,
      data_solicitacao: existente?.data_solicitacao,
      data_ultima_mudanca: existente?.data_ultima_mudanca,
      data_pagamento: existente?.data_pagamento,
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
    let dataMovimentacao = null; // data da movimentação vinda do modal

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
        // ❌ Nunca atualizamos data_ultima_mudanca aqui.
        // Ela SEMPRE será definida pela data da movimentação (modal).
        if (campo === "data_ultima_mudanca") {
          continue;
        }

        const dt = normalizarData(valor);
        if (!dt) continue;
        dataAtualizar[campo] = dt;
        continue;
      }

      dataAtualizar[campo] = valor;
    }

    if (Object.prototype.hasOwnProperty.call(dataAtualizar, "status")) {
      const novoStatus = dataAtualizar.status;

      if (novoStatus === "Pago") {
        // 🔹 Para "Pago", a data da movimentação deve ser a data de pagamento
        const dtPagamento =
          normalizarData(dados.dataPagamento ?? dados.data_pagamento) ||
          existente.data_pagamento ||
          getDataMovimentacaoFromBody(dados) ||
          existente.data_ultima_mudanca ||
          existente.data_solicitacao ||
          new Date();

        dataMovimentacao = dtPagamento;

        // Atualiza também a data de pagamento da solicitação
        dataAtualizar.data_pagamento = dtPagamento;
        dataAtualizar.data_ultima_mudanca = dtPagamento;
      } else {
        // 🔹 Demais status seguem a regra normal (statusDate, data, etc.)
        dataMovimentacao =
          getDataMovimentacaoFromBody(dados) ||
          existente.data_ultima_mudanca ||
          existente.data_solicitacao ||
          new Date();

        dataAtualizar.data_ultima_mudanca = dataMovimentacao;
      }

      if (novoStatus && novoStatus !== statusAntes) {
        statusMudou = true;
      }
    }

    console.log("DEBUG EDITAR - dataAtualizar:", {
      dataAtualizar,
      dataMovimentacao,
      statusAntes,
      statusDepois: dataAtualizar.status ?? statusAntes,
      statusMudou,
    });

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
          const obsHistorico = getObsFromBody(dados);
          const dataHistorico = dataMovimentacao || new Date();

          console.log("DEBUG EDITAR - HISTORICO A SER GRAVADO:", {
            solicitacao_id: solicitacaoId,
            status: atualizado.status,
            dataHistorico,
            origem: "Edição",
            obsHistorico,
          });

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

    const arquivo = await prisma.solicitacaoArquivo.findUnique({
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

    await prisma.solicitacaoArquivo.delete({
      where: { id: Number(id) },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erro em DELETE /arquivos/:id:", err);
    res.status(500).json({ erro: "Erro ao remover arquivo." });
  }
});

// =========================
// 🔰 HISTÓRICO DE STATUS (por solicitação)
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
      orderBy: { data: "asc" },
    });

    res.json(lista);
  } catch (err) {
    console.error("Erro em GET /solicitacoes/:id/historico:", err);
    res.status(500).json({ erro: "Erro ao buscar histórico." });
  }
});

// =========================
// 🔰 ATUALIZAR STATUS — KANBAN (com histórico)
// =========================
app.put(
  "/solicitacoes/:id/status",
  authMiddleware,
  adminOnly,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status, origem } = req.body;

      console.log("=== DEBUG KANBAN /status ===");
      console.log("ID:", id);
      console.log("Body recebido (req.body):", JSON.stringify(req.body, null, 2));
      console.log("Status solicitado:", status, "Origem recebida:", origem);

      // 📌 Observação / motivo (Kanban) — aqui NÃO usamos "descricao" para evitar herdar "Consulta"
      const textoObsRaw =
        req.body.obs ??
        req.body.observacao ??
        req.body.motivo ??
        req.body.motivoObs ??
        req.body["motivo_observacao"] ??
        "";

      const textoObs =
        textoObsRaw !== null && textoObsRaw !== undefined
          ? String(textoObsRaw).trim()
          : "";

      console.log("DEBUG KANBAN - OBS:", {
        textoObsRaw,
        textoObs,
      });

      // 📌 Motivo obrigatório para "Aguardando documento" e "Rejeitado"
      const motivoObrigatorio =
        status === "Aguardando documento" || status === "Rejeitado";

      if (motivoObrigatorio && !textoObs) {
        return res.status(400).json({
          erro:
            "Campo 'obs' (observação/motivo) é obrigatório quando o status é 'Aguardando documento' ou 'Rejeitado'.",
        });
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

      // 📌 Data da movimentação — sempre a do modal (em qualquer campo reconhecido)
      const dataMovimentacao =
        getDataMovimentacaoFromBody(req.body) || new Date();

      console.log("DEBUG KANBAN - DATA MOVIMENTACAO:", {
        recebido: {
          data_movimentacao: req.body.data_movimentacao,
          dataMovimentacao: req.body.dataMovimentacao,
          data_ultima_mudanca: req.body.data_ultima_mudanca,
          dataUltimaMudanca: req.body.dataUltimaMudanca,
          data: req.body.data,
          statusDate: req.body.statusDate,
        },
        dataMovimentacao,
      });

      const atualizado = await prisma.solicitacao.update({
        where: { id: Number(id) },
        data: {
          status,
          data_ultima_mudanca: dataMovimentacao,
        },
      });

      console.log("DEBUG KANBAN - HISTORICO A SER GRAVADO:", {
        solicitacao_id: Number(id),
        status,
        data: dataMovimentacao,
        origem: origem || "Sistema",
        obs: textoObs || null,
      });

      const Historico = getHistoricoModel();
      if (Historico) {
        await Historico.create({
          data: {
            solicitacao_id: Number(id),
            status,
            data: dataMovimentacao,
            origem: origem || "Sistema",
            obs: textoObs || null,
          },
        });
      }

      res.json({ ok: true, atualizado });
    } catch (err) {
      console.error("Erro em PUT /solicitacoes/:id/status:", err);
      res.status(500).json({ erro: "Erro ao atualizar status." });
    }
  }
);

// =========================
// 🔰 KANBAN
// =========================
app.get("/kanban", authMiddleware, adminOnly, async (req, res) => {
  try {
    const statusList = await prisma.status.findMany({
      where: { ativo: true },
      orderBy: { id: "asc" },
    });

    const solicitacoesRaw = await prisma.solicitacao.findMany({
      orderBy: { criado_em: "desc" },
      include: {
        arquivos: true,
        usuario: true,
      },
    });

    const solicitacoes = await attachHistoricoToSolicitacoes(solicitacoesRaw);

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

    const ultimas = await attachHistoricoToSolicitacoes(ultimasRaw);

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
app.get(
  "/config/estrutura-banco",
  authMiddleware,
  adminOnly,
  async (req, res) => {
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
  }
);

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
