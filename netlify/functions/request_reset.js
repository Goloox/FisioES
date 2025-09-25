// netlify/functions/request_reset.js
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

const {
  APP_BASE_URL,
  JWT_SECRET,
  // Puedes dejar SMTP_HOST/PORT vacíos: por defecto Gmail TLS 465
  SMTP_HOST = "smtp.gmail.com",
  SMTP_PORT = "465",
  SMTP_USER,
  SMTP_PASS,
} = process.env;

export const handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: JSON.stringify({ error: "Método no permitido" }) };
    }

    // Body
    let body;
    try { body = JSON.parse(event.body || "{}"); }
    catch { return { statusCode: 400, body: JSON.stringify({ error: "JSON inválido" }) }; }

    const correo = String(body.correo || "").trim().toLowerCase();
    if (!correo) return { statusCode: 400, body: JSON.stringify({ error: "Correo requerido" }) };

    // Requeridos
    if (!APP_BASE_URL || !JWT_SECRET) {
      return { statusCode: 500, body: JSON.stringify({ error: "Faltan APP_BASE_URL o JWT_SECRET" }) };
    }
    if (!SMTP_USER || !SMTP_PASS) {
      return { statusCode: 500, body: JSON.stringify({ error: "Faltan SMTP_USER/SMTP_PASS" }) };
    }

    // Generar token (15 min) y link
    const token = jwt.sign({ correo }, JWT_SECRET, { expiresIn: "15m" });
    const link = `${APP_BASE_URL}/reset.html?token=${encodeURIComponent(token)}`;

    // Transport Gmail (TLS 465)
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT),
      secure: Number(SMTP_PORT) === 465, // true para 465
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });

    // Opcional: confirma conexión/credenciales antes de enviar
    await transporter.verify();

    // Enviar SIEMPRE
    await transporter.sendMail({
      from: { name: "FISIOES Sistema", address: SMTP_USER },
      to: correo,
      subject: "Reestablecer contraseña • FISIOES",
      html: `
        <p>Hola,</p>
        <p>Solicitaste reestablecer tu contraseña. Enlace (válido por 15 minutos):</p>
        <p><a href="${link}" target="_blank" rel="noopener">${link}</a></p>
        <p>Si no fuiste tú, ignora este correo.</p>
      `,
      text: `Enlace (15 min): ${link}`,
    });

    // OK
    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (e) {
    // Muestra el error real en logs para depurar rápido
    console.error("request_reset error:", e?.message, e);
    return { statusCode: 500, body: JSON.stringify({ error: e?.message || "Error" }) };
  }
};
