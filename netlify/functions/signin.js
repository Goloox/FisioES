import bcrypt from "bcryptjs";
import { createRemoteJWKSet, jwtVerify } from "jose";

const { NEON_REST_URL, NEON_API_KEY, STACK_JWKS_URL, SIGNIN_REQUIRE_JWT } = process.env;

/**
 * Convierte un string a formato bytea hex para Postgres
 */
function toByteaHex(str) {
  const buf = Buffer.from(str, "utf8");
  return "\\x" + buf.toString("hex");
}

/**
 * Verifica JWT de Stack Auth (solo si está habilitado)
 */
async function verifyToken(authorization) {
  if (!authorization?.startsWith("Bearer ")) {
    throw new Error("Falta Authorization Bearer");
  }
  const token = authorization.slice("Bearer ".length).trim();
  const JWKS = createRemoteJWKSet(new URL(STACK_JWKS_URL));
  const { payload } = await jwtVerify(token, JWKS, {
    algorithms: ["ES256"],
  });
  return payload;
}

/**
 * Función Netlify
 */
export const handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: JSON.stringify({ error: "Method Not Allowed" }) };
    }

    if (!NEON_REST_URL || !NEON_API_KEY) {
      return {
        statusCode: 500,
        body: JSON.stringify({ error: "Faltan NEON_REST_URL o NEON_API_KEY" }),
      };
    }

    // 1) Verificar JWT (solo si SIGNIN_REQUIRE_JWT está en "true")
    let claims = {};
    if (SIGNIN_REQUIRE_JWT && SIGNIN_REQUIRE_JWT.toLowerCase() === "true") {
      if (!STACK_JWKS_URL) {
        return {
          statusCode: 500,
          body: JSON.stringify({ error: "Falta STACK_JWKS_URL" }),
        };
      }
      claims = await verifyToken(event.headers.authorization || event.headers.Authorization);
    }

    // 2) Leer body
    let body;
    try {
      body = JSON.parse(event.body || "{}");
    } catch {
      return { statusCode: 400, body: JSON.stringify({ error: "JSON inválido" }) };
    }

    const { nombre_completo, correo, cedula, password } = body;
    const errors = [];
    if (!nombre_completo || nombre_completo.trim().length < 3) errors.push("Nombre inválido");
    if (!correo || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(correo)) errors.push("Correo inválido");
    if (!cedula || cedula.trim().length < 3) errors.push("Cédula inválida");
    if (!password || String(password).length < 8) errors.push("La contraseña debe tener al menos 8 caracteres");

    if (errors.length) {
      return { statusCode: 400, body: JSON.stringify({ error: errors.join(", ") }) };
    }

    // 3) Hash con bcryptjs
    const hash = await bcrypt.hash(String(password), 10);
    const hashBytea = toByteaHex(hash);

    // 4) Insert Neon Data API
    const resp = await fetch(`${NEON_REST_URL}/usuario`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Prefer: "return=representation",
        apikey: NEON_API_KEY,
        Authorization: `Bearer ${NEON_API_KEY}`,
        "Content-Profile": "fisio",
        "Accept-Profile": "fisio",
      },
      body: JSON.stringify([
        {
          nombre_completo,
          correo,
          cedula,
          rol_id: 2,
          activo: 1,
          contrasena_hash: hashBytea,
        },
      ]),
    });

    const out = await resp.json();
    if (!resp.ok) {
      const msg =
        out?.message || out?.hint || out?.details || "No se pudo crear el usuario";
      return { statusCode: resp.status, body: JSON.stringify({ error: msg }) };
    }

    const usuario = Array.isArray(out) ? out[0] : out;
    if (usuario?.contrasena_hash) delete usuario.contrasena_hash;

    return {
      statusCode: 201,
      body: JSON.stringify({
        ok: true,
        usuario,
        claims,
      }),
    };
  } catch (e) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: e.message || "Error interno" }),
    };
  }
};
