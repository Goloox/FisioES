// netlify/functions/calendar_events_cita.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const rol = Number(claims.rol_id ?? claims.role_id ?? claims.role);
  if (rol !== 1) return { statusCode: 403, body: "Solo ADMIN" };

  const qs = event.queryStringParameters || {};
  const start = (qs.start || '').trim(); // ISO
  const end   = (qs.end   || '').trim(); // ISO
  if(!start || !end) return { statusCode:400, body:"start y end requeridos" };

  // Nota: si usas timestamp without time zone en DB, esto interpreta las cadenas como locales del servidor.
  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try{
    const sql = `
      SELECT c.id_cita, c.fecha, c.titulo, c.descripcion, c.estado,
             u.nombre_completo, u.correo
        FROM fisio.cita c
        JOIN fisio.usuario u ON u.id = c.usuario_id
       WHERE c.fecha >= $1::timestamp
         AND c.fecha <  $2::timestamp
       ORDER BY c.fecha ASC
    `;
    const r = await client.query(sql, [start, end]);

    // Formatear a "YYYY-MM-DDTHH:MM:00" para FullCalendar (local)
    const rows = r.rows.map(x => {
      const d = new Date(x.fecha); // ya local si guardas sin tz
      d.setSeconds(0,0);
      const pad = (n) => n<10 ? '0'+n : n;
      const startStr = d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes())+':00';
      return {
        ...x,
        start: startStr,
        end: null
      };
    });

    return { statusCode:200, headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ rows }) };
  }catch(e){
    return { statusCode:500, body:"Error: "+e.message };
  }finally{ try{ await client.end(); }catch{} }
};
