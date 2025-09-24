// netlify/functions/signin.js
import bcrypt from "bcryptjs";
import pg from "pg";

const { Pool } = pg;

// ¡Usamos TU DATABASE_URL de Neon!
const { DATABASE_URL, CORS_ALLOW_ORIGIN = "*" } = process.env;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": CORS_ALLOW_ORIGIN,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

// Pool de conexiones a Neon (usa el pooler y SSL de tu DATABASE_URL)
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }   // Neon requiere SSL
});

export const handler = async (event) => {
  try {
    // Preflight CORS
    if (event.httpMethod === "OPTIONS") {
      return { statusCode: 204, headers: CORS_HEADERS, body: "" };
    }
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, headers: CORS_HEADERS, body: JSON.stringify({ error: "Method Not Allowed" }) };
    }
    if (!DATABASE_URL) {
      return { statusCode: 500, headers: CORS_HEADERS, body: JSON.stringify({ error: "Falta DATABASE_URL" }) };
    }

    // Parse body
    let body;
    try { body = JSON.parse(event.body || "{}"); }
    catch { return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "JSON inválido" }) }; }

    const { nombre_completo, correo, cedula, password } = body;

    // Validaciones mínimas
    const errors = [];
    if (!nombre_completo || nombre_completo.trim().length < 3) errors.push("Nombre inválido");
    if (!correo || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(correo)) errors.push("Correo inválido");
    if (!cedula || cedula.trim().length < 3) errors.push("Cédula inválida");
    if (!password || String(password).length < 8) errors.push("Contraseña mínima 8 caracteres");
    if (errors.length) {
      return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: errors.join(", ") }) };
    }

    // Hash de contraseña (bcryptjs)
    const hash = await bcrypt.hash(String(password), 10);
    // Si tu columna es BYTEA (Postgres), envía un Buffer
    const hashBytea = Buffer.from(hash, "utf8");

    // Insert en fisio.usuario
    const sql = `
      INSERT INTO fisio.usuario
        (nombre_completo, correo, cedula, rol_id, activo, contrasena_hash)
      VALUES ($1, $2, $3, 2, 1, $4)
      RETURNING id, nombre_completo, correo, cedula, rol_id, activo, created_at, updated_at
    `;
    const params = [nombre_completo.trim(), correo.trim().toLowerCase(), cedula.trim(), hashBytea];

    const client = await pool.connect();
    try {
      const { rows } = await client.query(sql, params);
      const usuario = rows[0];

      return {
        statusCode: 201,
        headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
        body: JSON.stringify({ ok: true, usuario })
      };
    } finally {
      client.release();
    }
  } catch (e) {
    // Si hay violación de unicidad (correo/cedula), Postgres tira código 23505
    const msg = e?.detail || e?.message || "Error interno";
    const code = e?.code === "23505" ? 409 : 500;
    return { statusCode: code, headers: CORS_HEADERS, body: JSON.stringify({ error: msg }) };
  }
};
