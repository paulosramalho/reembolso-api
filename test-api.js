// test-api.js
// Script simples de validação da API Reembolso

require("dotenv").config();
const fetch = (...args) => import("node-fetch").then(({default: f}) => f(...args));

const API_URL = process.env.API_URL || "https://reembolso.onrender.com";

// Ajuste aqui para o admin que você já usa:
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "paulosramalho@gmail.com";
const ADMIN_SENHA = process.env.ADMIN_SENHA || "K!cks2024";
const ADMIN_ID = Number(process.env.ADMIN_ID || 4);

async function login() {
  console.log("🔐 Fazendo login como admin...");

  const res = await fetch(`${API_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: ADMIN_EMAIL, senha: ADMIN_SENHA }),
  });

  const data = await res.json();
  console.log("Resposta /auth/login:", data);

  if (!res.ok || !data.ok || !data.token) {
    throw new Error("Falha no login");
  }

  return data.token;
}

async function testSolicitacoesUsuario(token) {
  console.log("\n📄 Testando /solicitacoes/usuario/:id ...");

  const res = await fetch(`${API_URL}/solicitacoes/usuario/${ADMIN_ID}`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  const data = await res.json();
  console.log("Status HTTP:", res.status);
  console.log("Quantidade de solicitações retornadas:", Array.isArray(data) ? data.length : "não é array");
}

async function testSolicitacoesAdmin(token) {
  console.log("\n📊 Testando /solicitacoes (admin) ...");

  const res = await fetch(`${API_URL}/solicitacoes`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  const data = await res.json();
  console.log("Status HTTP:", res.status);
  console.log("Quantidade de solicitações retornadas:", Array.isArray(data) ? data.length : "não é array");
}

(async () => {
  try {
    const token = await login();
    await testSolicitacoesUsuario(token);
    await testSolicitacoesAdmin(token);
    console.log("\n✅ Testes concluídos.");
  } catch (err) {
    console.error("\n❌ Erro nos testes:", err);
  }
})();
