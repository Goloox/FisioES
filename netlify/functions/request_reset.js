import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

const { DATABASE_URL, RECAPTCHA_SECRET, APP_BASE_URL, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, JWT_SECRET } = process.env;

export const handler = async (event) => {
  try {
    if (event.httpMethod !== "POST")
      return { statusCode: 405, body: JSON.stringify({ error: "Método no permitido" }) };

    const { correo, captcha } = JSON.parse(event.body || "{}");
    if (!correo || !captcha) {
      return { statusCode: 400, body: JSON.stringify({ error: "Correo y captcha requeridos" }) };
    }

    // 1) Verificar reCAPTCHA
    const verify = await fetch(`https://www.google.com/recaptcha/api/siteverify`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret: RECAPTCHA_SECRET, response: captcha }),
    });
    const cap = await verify.json();
    if (!cap.success) return { statusCode: 400, body: JSON.stringify({ error: "Captcha inválido" }) };

    // 2) Generar token reset válido 15 min
    const token = jwt.sign({ correo }, JWT_SECRET, { expiresIn: "15m" });
    const link = `${APP_BASE_URL}/reset.html?token=${token}`;

    // 3) Enviar correo
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });

    await transporter.sendMail({
      from: `"FISIOES Sistema" <${SMTP_USER}>`,
      to: correo,
      subject: "Reestablecer contraseña - FISIOES",
      html: `
        <p>Hola,</p>
        <p>Solicitaste reestablecer tu contraseña. Haz clic en el siguiente enlace:</p>
        <p><a href="${link}">${link}</a></p>
        <p>El enlace expira en 15 minutos.</p>
      `,
    });

    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
