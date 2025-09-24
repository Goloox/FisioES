import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const { DATABASE_URL, JWT_SECRET } = process.env;

export const handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: JSON.stringify({ error: "Method Not Allowed" }) };
    }

    if (!DATABASE_URL || !JWT_SECRET) {
      return { statusCode: 500, body: JSON.stringify({ error: "Falta DATABASE_URL o JWT_SECRET" }) };
    }

    // 1) Body
    let body;
    try {
      body = JSON.parse(event.body || "{}");
    } catch {
      return { statusCode: 400, body: JSON.stringify({ error: "JSON inválido" }) };
    }

    const { correo, password } = body;
    if (!correo || !password) {
      return { statusCode: 400, body: JSON.stringify({ error: "Correo y contraseña requeridos" }) };
    }

    // 2) Buscar usuario en Neon vía SQL directo (ejemplo con Postgres npm lib)
    const { Client } = await import("pg");
    const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await client.connect();
    const result = await client.query("SELECT * FROM fisio.usuario WHERE correo = $1", [correo]);
    await client.end();

    if (result.rows.length === 0) {
      return { statusCode: 401, body: JSON.stringify({ error: "Usuario no encontrado" }) };
    }

    const user = result.rows[0];

    // 3) Comparar contraseña
    const ok = await bcrypt.compare(password, Buffer.from(user.contrasena_hash).toString("utf8"));
    if (!ok) {
      return { statusCode: 401, body: JSON.stringify({ error: "Contraseña incorrecta" }) };
    }

    // 4) Generar JWT (expira en 1h)
    const token = jwt.sign(
      { id: user.id, correo: user.correo, rol_id: user.rol_id },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    delete user.contrasena_hash;

    return {
      statusCode: 200,
      body: JSON.stringify({ ok: true, token, usuario: user }),
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
