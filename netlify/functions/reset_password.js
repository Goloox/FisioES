// netlify/functions/reset_password.js
import bcrypt from "bcryptjs";
import crypto from "crypto";
import pkg from "pg";
const { Client } = pkg;

const {
  DATABASE_URL,
  RECAPTCHA_SECRET
} = process.env;

async function verifyCaptcha(responseToken) {
  if (!RECAPTCHA_SECRET) throw new Error("Falta RECAPTCHA_SECRET");
  const res = await fetch("https://www.google.com/recaptcha/api/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      secret: RECAPTCHA_SECRET,
      response: responseToken
    })
  });
  const data = await res.json();
  if (!data.success) throw new Error("Captcha inválido");
}

export const handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: JSON.stringify({ error: "Method Not Allowed" }) };
    }
    if (!DATABASE_URL) {
      return { statusCode: 500, body: JSON.stringify({ error: "Falta DATABASE_URL" }) };
    }

    let body;
    try { body = JSON.parse(event.body || "{}"); }
    catch { return { statusCode: 400, body: JSON.stringify({ error: "JSON inválido" }) }; }

    const { token, password, captcha } = body;
    if (!token || !password || !captcha) {
      return { statusCode: 400, body: JSON.stringify({ error: "Token, contraseña y captcha requeridos" }) };
    }
    if (String(password).length < 8) {
      return { statusCode: 400, body: JSON.stringify({ error: "La contraseña debe tener al menos 8 caracteres" }) };
    }

    await verifyCaptcha(captcha);

    const token_hash = crypto.createHash("sha256").update(token).digest(); // Buffer

    const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await client.connect();

    // Obtener solicitud válida
    const q = await client.query(
      `SELECT pr.id, pr.user_id, pr.expires_at, pr.used_at
       FROM fisio.password_reset pr
       WHERE pr.token_hash = $1
       ORDER BY pr.created_at DESC
       LIMIT 1`,
      [token_hash]
    );

    if (q.rows.length === 0) {
      await client.end();
      return { statusCode: 400, body: JSON.stringify({ error: "Token inválido" }) };
    }

    const req = q.rows[0];
    if (req.used_at) {
      await client.end();
      return { statusCode: 400, body: JSON.stringify({ error: "Token ya usado" }) };
    }
    if (new Date(req.expires_at).getTime() < Date.now()) {
      await client.end();
      return { statusCode: 400, body: JSON.stringify({ error: "Token expirado" }) };
    }

    // Hash de la nueva contraseña (BYTEA)
    const hash = await bcrypt.hash(String(password), 10);
    const hashBytea = Buffer.from(hash, "utf8");

    // Actualizar usuario y marcar token usado (transacción simple)
    await client.query("BEGIN");
    await client.query(
      `UPDATE fisio.usuario SET contrasena_hash = $1 WHERE id = $2`,
      [hashBytea, req.user_id]
    );
    await client.query(
      `UPDATE fisio.password_reset SET used_at = now() WHERE id = $1`,
      [req.id]
    );
    await client.query("COMMIT");
    await client.end();

    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message || "Error" }) };
  }
};
