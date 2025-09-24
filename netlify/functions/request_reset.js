// netlify/functions/request_reset.js
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { Client } from "pg";

const {
  APP_BASE_URL,
  JWT_SECRET,
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
  DATABASE_URL,
} = process.env;

export const handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: JSON.stringify({ error: "Método no permitido" }) };
    }

    let body;
    try { body = JSON.parse(event.body || "{}"); }
    catch { return { statusCode: 400, body: JSON.stringify({ error: "JSON inválido" }) }; }

    const correo = String(body.correo || "").trim().toLowerCase();
    if (!correo) {
      return { statusCode: 400, body: JSON.stringify({ error: "Correo requerido" }) };
    }

    // Validación de env vars
    if (!APP_BASE_URL || !JWT_SECRET) {
      return { statusCode: 500, body: JSON.stringify({ error: "Faltan APP_BASE_URL o JWT_SECRET" }) };
    }
    if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) {
      return { statusCode: 500, body: JSON.stringify({ error: "Faltan variables SMTP_*" }) };
    }
    if (!DATABASE_URL) {
      return { statusCode: 500, body: JSON.stringify({ error: "Falta DATABASE_URL" }) };
    }

    // Verificar si el correo existe (no revelarlo en la respuesta)
    const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await client.connect();
    const u = await client.query(
      "SELECT id, nombre_completo FROM fisio.usuario WHERE correo = $1 LIMIT 1",
      [correo]
    );
    await client.end();

    // Generar token (15 min)
    const token = jwt.sign({ correo }, JWT_SECRET, { expiresIn: "15m" });
    const link = `${APP_BASE_URL}/reset.html?token=${encodeURIComponent(token)}`;

    // Si el usuario existe, enviar correo
    if (u.rows.length > 0) {
      const nombre = u.rows[0].nombre_completo || "";

      const transporter = nodemailer.createTransport({
        host: SMTP_HOST,                          // smtp.gmail.com
        port: Number(SMTP_PORT),                  // 465 recomendado
        secure: Number(SMTP_PORT) === 465,        // true si 465, false si 587
        auth: { user: SMTP_USER, pass: SMTP_PASS }
      });

      await transporter.sendMail({
        from: { name: "FISIOES Sistema", address: SMTP_USER }, // Gmail respeta el address
        to: correo,
        subject: "Reestablecer contraseña • FISIOES",
        html: `
          <p>Hola ${nombre ? nombre + "," : ""}</p>
          <p>Solicitaste reestablecer tu contraseña. Haz clic en el siguiente enlace (válido por 15 minutos):</p>
          <p><a href="${link}" target="_blank" rel="noopener">${link}</a></p>
          <p>Si no fuiste tú, ignora este correo.</p>
        `,
        text: `Enlace para reestablecer contraseña (15 min): ${link}`
      });
    }

    // Siempre OK para no filtrar existencia de usuarios
    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message || "Error" }) };
  }
};
