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
  const safeFail = (status, msg, debug) => {
    // No exponemos detalles sensibles al frontend
    console.log("request_reset error:", debug || msg);
    return { statusCode: status, body: JSON.stringify({ error: msg }) };
  };

  try {
    if (event.httpMethod !== "POST") {
      return safeFail(405, "Método no permitido");
    }

    let body;
    try { body = JSON.parse(event.body || "{}"); }
    catch { return safeFail(400, "JSON inválido"); }

    const correo = String(body.correo || "").trim().toLowerCase();
    if (!correo) return safeFail(400, "Correo requerido");

    if (!APP_BASE_URL || !JWT_SECRET) {
      return safeFail(500, "Faltan APP_BASE_URL o JWT_SECRET");
    }
    // SMTP y BD los validamos pero no romperemos el flujo si fallan;
    // priorizamos que la función responda 200 para no romper la UI.
    const hasSMTP = SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS;
    const hasDB = !!DATABASE_URL;

    // Token de 15 min
    const token = jwt.sign({ correo }, JWT_SECRET, { expiresIn: "15m" });
    const link = `${APP_BASE_URL}/reset.html?token=${encodeURIComponent(token)}`;

    // 1) (Opcional) verificar existencia del usuario en BD
    let userExists = true; // por defecto, para no filtrar
    if (hasDB) {
      try {
        const client = new Client({
          connectionString: DATABASE_URL,
          ssl: { rejectUnauthorized: false },
        });
        await client.connect();
        const q = await client.query(
          "SELECT 1 FROM fisio.usuario WHERE correo = $1 LIMIT 1",
          [correo]
        );
        userExists = q.rowCount > 0;
        await client.end();
      } catch (dbErr) {
        console.log("DB check failed, proceeding anyway:", dbErr?.message);
        // seguimos sin romper
      }
    } else {
      console.log("DATABASE_URL ausente: se omite verificación en BD");
    }

    // 2) Enviar correo solo si existe (no revelamos esto al cliente)
    if (userExists && hasSMTP) {
      try {
        const transporter = nodemailer.createTransport({
          host: SMTP_HOST,
          port: Number(SMTP_PORT),
          secure: Number(SMTP_PORT) === 465, // Gmail: 465 = TLS
          auth: { user: SMTP_USER, pass: SMTP_PASS },
        });

        // Verificación opcional del transporte (ayuda a detectar 535 rápidamente)
        await transporter.verify();

        await transporter.sendMail({
          from: { name: "FISIOES Sistema", address: SMTP_USER },
          to: correo,
          subject: "Reestablecer contraseña • FISIOES",
          html: `
            <p>Hola,</p>
            <p>Solicitaste reestablecer tu contraseña. Enlace válido por 15 minutos:</p>
            <p><a href="${link}" target="_blank" rel="noopener">${link}</a></p>
            <p>Si no fuiste tú, ignora este correo.</p>
          `,
          text: `Enlace (15 min): ${link}`,
        });
      } catch (smtpErr) {
        // No rompemos la UI. Queda logueado para revisar en Netlify → Deploys → Functions → Logs
        console.log("SMTP send failed:", smtpErr?.message);
      }
    } else if (!hasSMTP) {
      console.log("SMTP vars ausentes: no se intentó enviar el correo");
    }

    // 3) Siempre OK para no filtrar existencia
    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (e) {
    return safeFail(500, "Error interno", e?.message);
  }
};
