// netlify/functions/signin.js
import argon2 from 'argon2';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const {
  NEON_REST_URL,
  NEON_API_KEY,
  STACK_JWKS_URL,
  SIGNIN_REQUIRE_JWT = 'false',        // <-- pon "true" cuando ya tengas el token de Stack listo
  CORS_ALLOW_ORIGIN = '*',             // <-- o cambia a tu dominio: https://tusitio.netlify.app
} = process.env;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': CORS_ALLOW_ORIGIN,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function toByteaHex(str) {
  return '\\x' + Buffer.from(str, 'utf8').toString('hex');
}

async function verifyTokenIfRequired(authorization) {
  const requireJwt = String(SIGNIN_REQUIRE_JWT).toLowerCase() === 'true';
  if (!requireJwt) return { sub: 'dev-no-jwt' }; // modo debug

  if (!authorization?.startsWith('Bearer ')) {
    throw new Error('Falta Authorization Bearer');
  }
  const token = authorization.slice('Bearer '.length).trim();
  if (!STACK_JWKS_URL) throw new Error('Falta STACK_JWKS_URL');

  const JWKS = createRemoteJWKSet(new URL(STACK_JWKS_URL));
  const { payload } = await jwtVerify(token, JWKS, { algorithms: ['ES256'] });
  return payload; // ej: { sub, email, ... }
}

export const handler = async (event) => {
  try {
    // Preflight CORS
    if (event.httpMethod === 'OPTIONS') {
      return { statusCode: 204, headers: CORS_HEADERS, body: '' };
    }

    if (event.httpMethod !== 'POST') {
      return { statusCode: 405, headers: CORS_HEADERS, body: JSON.stringify({ error: 'Method Not Allowed' }) };
    }

    if (!NEON_REST_URL || !NEON_API_KEY) {
      return { statusCode: 500, headers: CORS_HEADERS, body: JSON.stringify({ error: 'Faltan NEON_REST_URL o NEON_API_KEY' }) };
    }

    // 1) Verificar JWT si es requerido
    let claims;
    try {
      claims = await verifyTokenIfRequired(event.headers.authorization || event.headers.Authorization);
    } catch (e) {
      return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: e.message || 'No autorizado' }) };
    }

    // 2) Parsear body
    let body;
    try { body = JSON.parse(event.body || '{}'); }
    catch { return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: 'JSON inválido' }) }; }

    const { nombre_completo, correo, cedula, password } = body;
    const errors = [];
    if (!nombre_completo || nombre_completo.trim().length < 3) errors.push('Nombre inválido');
    if (!correo || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(correo)) errors.push('Correo inválido');
    if (!cedula || cedula.trim().length < 3) errors.push('Cédula inválida');
    if (!password || String(password).length < 8) errors.push('La contraseña debe tener al menos 8 caracteres');
    if (errors.length) {
      return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: errors.join(', ') }) };
    }

    // 3) Hash seguro (argon2id)
    const hash = await argon2.hash(String(password), { type: argon2.argon2id });
    const hashBytea = toByteaHex(hash);

    // 4) Insert en Neon (schema fisio)
    const resp = await fetch(`${NEON_REST_URL}/usuario`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
        'apikey': NEON_API_KEY,
        'Authorization': `Bearer ${NEON_API_KEY}`,
        'Content-Profile': 'fisio',
        'Accept-Profile': 'fisio'
      },
      body: JSON.stringify([{
        nombre_completo,
        correo,
        cedula,
        rol_id: 2,
        activo: 1,
        contrasena_hash: hashBytea,
        // auth_sub: claims.sub, // si decides agregar la columna
      }])
    });

    const text = await resp.text();
    let out;
    try { out = JSON.parse(text); } catch { out = { raw: text }; }

    if (!resp.ok) {
      // Devuelve el detalle exacto para depurar (duplicados, RLS, etc.)
      const msg = out?.message || out?.hint || out?.details || out?.raw || 'No se pudo crear el usuario';
      return { statusCode: resp.status, headers: CORS_HEADERS, body: JSON.stringify({ error: msg, neon: out }) };
    }

    const usuario = Array.isArray(out) ? out[0] : out;
    if (usuario && 'contrasena_hash' in usuario) delete usuario.contrasena_hash;

    return { statusCode: 201, headers: CORS_HEADERS, body: JSON.stringify({ ok: true, usuario, claims: { sub: claims.sub } }) };
  } catch (e) {
    // Cualquier otra excepción
    return { statusCode: 500, headers: CORS_HEADERS, body: JSON.stringify({ error: e.message || 'Error interno' }) };
  }
};
