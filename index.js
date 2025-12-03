// index.js - API Reembolso

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");

const app = express();
const prisma = new PrismaClient();

// Porta: usa a do .env (4000) ou 3000 se não tiver
const PORT = process.env.PORT || 3000;
const APP_BASE_URL = process.env.APP_BASE_URL || "";

// Middlewares
app.use(express.json());

// 🔓 CORS
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
];

if (APP_BASE_URL) {
  // usa exatamente o que vier do .env
  allowedOrigins.push(APP_BASE_URL);

  // se não tiver protocolo, adiciona versões http/https
  if (!APP_BASE_URL.startsWith("http")) {
    allowedOrigins.push(`https://${APP_BASE_URL}`);
    allowedOrigins.push(`http://${APP_BASE_URL}`);
  }
}

app.use(
  cors({
    origin(origin, callback) {
      // permite ferramentas tipo Postman (origin undefined)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Não permitido pelo CORS"), false);
    },
    credentials: true,
  })
);

// 🔍 Healthcheck (Render, uptime robot, etc. usam isso)
app.get("/health", async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Erro no healthcheck:", err);
    res
      .status(500)
      .json({ status: "error", message: "DB indisponível" });
  }
});

// 🌐 Rota raiz
app.get("/", (req, res) => {
  res.send("API Reembolso rodando.");
});

// (no futuro, quando tivermos as rotas de negócio, adicionamos aqui)
// ex:
// const authRoutes = require("./routes/auth");
// app.use("/auth", authRoutes);

// 🧯 Middleware de erro genérico
app.use((err, req, res, next) => {
  console.error("Erro não tratado:", err);
  res.status(500).json({ error: "Erro interno do servidor" });
});

// ▶️ Start
app.listen(PORT, () => {
  console.log(`🚀 API Reembolso rodando na porta ${PORT}`);
});
