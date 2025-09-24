// netlify/functions/reset_password.js
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Client } from "pg";

const { DATABASE_URL, JWT_SECRET } = process.env;

export const handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: JSON.stringify({ error: "Método no permitido" }) };
    }
    if (!DATABASE_URL || !JWT_SECRET) {
      return { statusCode: 500, body: JSON.stringify({ error: "Falta DATABASE_URL o JWT_SECRET" }) };
    }

    let body;
    try { body = JSON.parse(event.body || "{}"); }
    catch { return { statusCode: 400, body: JSON.stringify({ error: "JSON inválido" }) }; }

    const { token, password } = body;
    if (!token || !password) {
      return { statusCode: 400, body: JSON.stringify({ error: "Token y contraseña requeridos" }) };
    }
    if (String(password).length < 8) {
      return { statusCode: 400, body: JSON.stringify({ error: "La contraseña debe tener al menos 8 caracteres" }) };
    }

    // Verificar token
    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return { statusCode: 400, body: JSON.stringify({ error: "Token inválido o caducado" }) };
    }
    const correo = String(payload.correo || "").toLowerCase();

    // Hash y actualizar en BD
    const hash = await bcrypt.hash(password, 10);

    const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await client.connect();

    // Si tu columna contrasena_hash es BYTEA, guarda como Buffer:
    const hashBytea = Buffer.from(hash, "utf8");
    const r = await client.query(
      "UPDATE fisio.usuario SET contrasena_hash = $1 WHERE correo = $2",
      [hashBytea, correo]
    );

    // Si en tu esquema fuera TEXT/VARCHAR, usar esta línea en su lugar:
    // const r = await client.query("UPDATE fisio.usuario SET contrasena_hash = $1 WHERE correo = $2", [hash, correo]);

    await client.end();

    if (r.rowCount === 0) {
      return { statusCode: 400, body: JSON.stringify({ error: "Usuario no encontrado" }) };
    }

    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message || "Error" }) };
  }
};
