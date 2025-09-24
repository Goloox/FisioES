import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Client } from "pg";

const { DATABASE_URL, RECAPTCHA_SECRET, JWT_SECRET } = process.env;

export const handler = async (event) => {
  try {
    if (event.httpMethod !== "POST")
      return { statusCode: 405, body: JSON.stringify({ error: "Método no permitido" }) };

    const { token, password, captcha } = JSON.parse(event.body || "{}");
    if (!token || !password || !captcha) {
      return { statusCode: 400, body: JSON.stringify({ error: "Faltan datos" }) };
    }

   
    // 2) Verificar token
    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return { statusCode: 400, body: JSON.stringify({ error: "Token inválido o caducado" }) };
    }

    const correo = payload.correo;

    // 3) Actualizar password en BD
    const hash = await bcrypt.hash(password, 10);

    const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await client.connect();
    await client.query("UPDATE fisio.usuario SET contrasena_hash = $1 WHERE correo = $2", [hash, correo]);
    await client.end();

    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
