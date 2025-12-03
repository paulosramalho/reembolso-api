// index.js - API Reembolso (produção)

// 1) Dependências básicas
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");

// 2) Instâncias
const app = express();
const prisma = new PrismaClient();

// 3) Variáveis de ambiente importantes
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const APP_BASE_URL = process.env.APP_BASE_URL; // ex: "controle-de-reembolso.vercel.app"

if (!DATABASE_URL) {
  console.warn("⚠️  DATABASE_URL não está definida. Verifique as variáveis de ambiente no Render.");
}

// 4) Middlewares
app.use(express.json());

// CORS — libera frontend em produção + localhost
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
];

if (APP_BASE_URL) {
  allowedOrigins.push(`https://${APP_BASE_URL}`);
  allowedOrigins.push(`http://${APP_BASE_URL}`);
}

app.use(
  cors({
    origin: (origin, callback) => {
      // permite ferramentas tipo Postman (origin undefined)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Não permitido pelo CORS"), false);
    },
    credentials: true,
  })
);

// 5) Rota de saúde (healthcheck)
app.get("/health", async (req, res) => {
  try {
    // teste simples no banco (opcional, mas bom pra saúde real)
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Erro no healthcheck:", err);
    res.status(500).json({ status: "error", message: "DB indisponível" });
  }
});

// 6) Rota raiz (útil também como health se quiser configurar assim no Render)
app.get("/", (req, res) => {
  res.send("API Reembolso rodando.");
});

// 7) Suas rotas existentes (mantenha/encaixe aqui)
try {
  const authRoutes = require("./routes/authRoutes");
  const usuariosRoutes = require("./routes/usuariosRoutes");
  const solicitacoesRoutes = require("./routes/solicitacoesRoutes");
  // adicione outras se tiver

  app.use("/auth", authRoutes);
  app.use("/usuarios", usuariosRoutes);
  app.use("/solicitacoes", solicitacoesRoutes);

} catch (err) {
  console.warn("⚠️ Não foi possível carregar alguma rota. Verifique os paths em index.js");
  console.warn(err.message);
}

// 8) Middleware de erro genérico (opcional, mas ajuda debug)
app.use((err, req, res, next) => {
  console.error("Erro não tratado:", err);
  res.status(500).json({ error: "Erro interno do servidor" });
});

// 9) Start do servidor
app.listen(PORT, () => {
  console.log(`🚀 API Reembolso rodando na porta ${PORT}`);
});
