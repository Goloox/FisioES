// netlify/functions/request_reset.js
import crypto from "crypto";
import pkg from "pg";
const { Client } = pkg;

const {
  DATABASE_URL,
  RECAPTCHA_SECRET,     // tu clave secreta de reCAPTCHA
  APP_BASE_URL,         // ej: https://fisioes.netlify.app
  RESEND_API_KEY,       // si usas Resend para enviar correo
  RESEND_FROM = "FISIOES <noreply@yourdomain.com>"
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

async function sendEmail(to, subject, html) {
  if (!RESEND_API_KEY) {
    console.log("RESEND_API_KEY no configurado. Enviaría a:", to, "Asunto:", subject, html);
    return;
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: RESEND_FROM,
      to,
      subject,
      html
    })
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Fallo enviando email: ${t}`);
  }
}

export const handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: JSON.stringify({ error: "Method Not Allowed" }) };
    }
    if (!DATABASE_URL || !APP_BASE_URL) {
      return { statusCode: 500, body: JSON.stringify({ error: "Falta DATABASE_URL o APP_BASE_URL" }) };
    }

    let body;
    try { body = JSON.parse(event.body || "{}"); }
    catch { return { statusCode: 400, body: JSON.stringify({ error: "JSON inválido" }) }; }

    const { correo, captcha } = body;
    if (!correo || !captcha) {
      return { statusCode: 400, body: JSON.stringify({ error: "Correo y captcha requeridos" }) };
    }

    await verifyCaptcha(captcha);

    const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await client.connect();

    // Buscar usuario
    const u = await client.query("SELECT id, nombre_completo FROM fisio.usuario WHERE correo = $1", [correo.trim().toLowerCase()]);
    if (u.rows.length === 0) {
      await client.end();
      // No revelamos si no existe: respondemos OK igual
      return { statusCode: 200, body: JSON.stringify({ ok: true }) };
    }

    const user = u.rows[0];

    // Generar token
    const token = crypto.randomBytes(32).toString("hex");
    const token_hash = crypto.createHash("sha256").update(token).digest(); // Buffer
    const expires_at = new Date(Date.now() + 1000 * 60 * 15); // 15 min

    // Guardar en BD
    await client.query(
      `INSERT INTO fisio.password_reset (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
      [user.id, token_hash, expires_at]
    );

    await client.end();

    const link = `${APP_BASE_URL}/reset.html?token=${token}`;
    const html = `
      <p>Hola ${user.nombre_completo || ""},</p>
      <p>Has solicitado reestablecer tu contraseña. Haz clic en el siguiente enlace (válido por 15 minutos):</p>
      <p><a href="${link}">${link}</a></p>
      <p>Si no fuiste tú, ignora este correo.</p>
    `;

    await sendEmail(correo, "Reestablecer contraseña • FISIOES", html);

    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message || "Error" }) };
  }
};
