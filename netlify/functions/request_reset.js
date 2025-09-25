import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

const {
  APP_BASE_URL,
  JWT_SECRET,
  SMTP_HOST = "smtp.gmail.com",
  SMTP_PORT,               // opcional: si no lo pones, probamos 465 y 587
  SMTP_USER,
  SMTP_PASS,
} = process.env;

async function sendMailAny(transporterOpts, mail) {
  const t = nodemailer.createTransport(transporterOpts);
  await t.verify();
  return t.sendMail(mail);
}

export const handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: JSON.stringify({ error: "Método no permitido" }) };
    }

    let body; try { body = JSON.parse(event.body || "{}"); }
    catch { return { statusCode: 400, body: JSON.stringify({ error: "JSON inválido" }) }; }

    const correo = String(body.correo || "").trim().toLowerCase();
    if (!correo) return { statusCode: 400, body: JSON.stringify({ error: "Correo requerido" }) };
    if (!APP_BASE_URL || !JWT_SECRET) {
      return { statusCode: 500, body: JSON.stringify({ error: "Faltan APP_BASE_URL o JWT_SECRET" }) };
    }
    if (!SMTP_USER || !SMTP_PASS) {
      return { statusCode: 500, body: JSON.stringify({ error: "Faltan SMTP_USER/SMTP_PASS" }) };
    }

    const token = jwt.sign({ correo }, JWT_SECRET, { expiresIn: "15m" });
    const link = `${APP_BASE_URL}/reset.html?token=${encodeURIComponent(token)}`;

    const mail = {
      from: { name: "FISIOES Sistema", address: SMTP_USER },
      to: correo,
      subject: "Reestablecer contraseña • FISIOES",
      html: `<p>Hola,</p>
             <p>Enlace para reestablecer tu contraseña (15 minutos):</p>
             <p><a href="${link}" target="_blank" rel="noopener">${link}</a></p>
             <p>Si no fuiste tú, ignora este correo.</p>`,
      text: `Enlace (15 min): ${link}`,
    };

    // 1) Si diste un puerto, respétalo; si no, probamos 465 y luego 587
    const tries = SMTP_PORT
      ? [{
          host: SMTP_HOST, port: Number(SMTP_PORT),
          secure: Number(SMTP_PORT) === 465,
          auth: { user: SMTP_USER, pass: SMTP_PASS },
        }]
      : [
          { host: SMTP_HOST, port: 465, secure: true,  auth: { user: SMTP_USER, pass: SMTP_PASS } }, // TLS
          { host: SMTP_HOST, port: 587, secure: false, auth: { user: SMTP_USER, pass: SMTP_PASS }, requireTLS: true } // STARTTLS
        ];

    let lastErr;
    for (const cfg of tries) {
      try {
        await sendMailAny(cfg, mail);
        return { statusCode: 200, body: JSON.stringify({ ok: true }) };
      } catch (e) {
        lastErr = e;
        console.error("SMTP intento falló:", cfg.port, e?.message);
      }
    }

    // Si llegamos aquí, fallaron todos los intentos
    return { statusCode: 500, body: JSON.stringify({ error: lastErr?.message || "Fallo al enviar correo" }) };
  } catch (e) {
    console.error("request_reset error:", e);
    return { statusCode: 500, body: JSON.stringify({ error: e?.message || "Error" }) };
  }
};
