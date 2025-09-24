import argon2 from 'argon2';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const { NEON_REST_URL, NEON_API_KEY, STACK_JWKS_URL } = process.env;

function toByteaHex(str) {
  const buf = Buffer.from(str, 'utf8');
  return '\\x' + buf.toString('hex');
}

async function verifyToken(authorization) {
  if (!authorization?.startsWith('Bearer ')) {
    throw new Error('Falta Authorization Bearer');
  }
  const token = authorization.slice('Bearer '.length).trim();
  const JWKS = createRemoteJWKSet(new URL(STACK_JWKS_URL));
  const { payload } = await jwtVerify(token, JWKS, {
    algorithms: ['ES256'] // tus llaves son P-256 ES256
  });
  return payload; // sub, email, etc.
}

export const handler = async (event) => {
  try {
    if (event.httpMethod !== 'POST') {
      return { statusCode: 405, body: JSON.stringify({ error: 'Method Not Allowed' }) };
    }
    if (!NEON_REST_URL || !NEON_API_KEY) {
      return { statusCode: 500, body: JSON.stringify({ error: 'Faltan NEON_REST_URL o NEON_API_KEY' }) };
    }
    if (!STACK_JWKS_URL) {
      return { statusCode: 500, body: JSON.stringify({ error: 'Falta STACK_JWKS_URL' }) };
    }

    // 1) Verificar JWT
    const claims = await verifyToken(event.headers.authorization || event.headers.Authorization);

    // 2) Leer body
    let body;
    try { body = JSON.parse(event.body || '{}'); }
    catch { return { statusCode: 400, body: JSON.stringify({ error: 'JSON inválido' }) }; }

    const { nombre_completo, correo, cedula, password } = body;
    const errors = [];
    if (!nombre_completo || nombre_completo.trim().length < 3) errors.push('Nombre inválido');
    if (!correo || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(correo)) errors.push('Correo inválido');
    if (!cedula || cedula.trim().length < 3) errors.push('Cédula inválida');
    if (!password || String(password).length < 8) errors.push('La contraseña debe tener al menos 8 caracteres');
    if (errors.length) return { statusCode: 400, body: JSON.stringify({ error: errors.join(', ') }) };

    // 3) Hash
    const hash = await argon2.hash(String(password), { type: argon2.argon2id });
    const hashBytea = toByteaHex(hash);

    // 4) Insert Neon Data API
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
        nombre_completo, correo, cedula,
        rol_id: 2, activo: 1,
        contrasena_hash: hashBytea,
        // auth_sub: claims.sub // si agregas esta columna en tu tabla
      }])
    });

    const out = await resp.json();
    if (!resp.ok) {
      const msg = out?.message || out?.hint || out?.details || 'No se pudo crear el usuario';
      return { statusCode: resp.status, body: JSON.stringify({ error: msg }) };
    }
    const usuario = Array.isArray(out) ? out[0] : out;
    delete usuario?.contrasena_hash;

    return { statusCode: 201, body: JSON.stringify({ ok: true, usuario, claims: { sub: claims.sub } }) };
  } catch (e) {
    return { statusCode: 401, body: JSON.stringify({ error: e.message || 'No autorizado' }) };
  }
};
