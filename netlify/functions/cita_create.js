// netlify/functions/cita_create.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

function normalizeFullHourLocal(str){
  // Espera "YYYY-MM-DDTHH:MM" o "YYYY-MM-DDTHH:MM:SS"
  if(!str || typeof str !== 'string') return null;
  const [date, time] = str.split('T');
  if(!date || !time) return null;
  const parts = time.split(':');
  const hh = parts[0] ?? '00';
  // fuerza minutos y segundos a 00
  const h = String(Math.max(0, Math.min(23, parseInt(hh,10)))).padStart(2,'0');
  return `${date}T${h}:00:00`;
}

export const handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { body = {}; }

  let { fecha, titulo, descripcion } = body;
  titulo = (titulo || '').trim();
  descripcion = (descripcion || '').trim();

  if (!fecha || !titulo) {
    return { statusCode: 400, body: "fecha y titulo son requeridos" };
  }

  // Si viene en ISO con 'Z', lo convertimos a local y cortamos a HH:00:00
  if (/\dZ$/.test(fecha) || fecha.endsWith('Z')) {
    const d = new Date(fecha);
    if (isNaN(d)) return { statusCode: 400, body: "fecha inválida" };
    // a local "YYYY-MM-DDTHH:MM"
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth()+1).padStart(2,'0');
    const dd = String(d.getDate()).padStart(2,'0');
    const HH = String(d.getHours()).padStart(2,'0');
    fecha = `${yyyy}-${mm}-${dd}T${HH}:00`;
  }

  const fechaLocal = normalizeFullHourLocal(fecha);
  if (!fechaLocal) {
    return { statusCode: 400, body: "fecha inválida" };
  }

  // Guardamos como TIMESTAMP sin zona. Postgres aceptará "YYYY-MM-DD HH:MM:SS"
  const fechaSql = fechaLocal.replace('T',' '); // "YYYY-MM-DD HH:00:00"

  const usuario_id = Number(claims.id || claims.user_id || claims.sub || claims.usuario_id);
  if (!usuario_id) return { statusCode: 400, body: "usuario no válido" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    const ins = await client.query(
      `INSERT INTO fisio.cita (fecha, titulo, descripcion, usuario_id, estado)
       VALUES ($1::timestamp, $2, $3, $4, 3)
       RETURNING id_cita, fecha, titulo, descripcion, usuario_id, estado`,
      [fechaSql, titulo, descripcion || null, usuario_id]
    );

    return {
      statusCode: 201,
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ ok:true, row:ins.rows[0] })
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
