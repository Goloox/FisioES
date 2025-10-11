// netlify/functions/cita_list_all_upcoming.js
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
  const page = Math.max(1, parseInt(qs.page || "1", 10));
  const pageSize = Math.min(100, Math.max(1, parseInt(qs.pageSize || "10", 10)));
  const q = (qs.q || "").trim();

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();

  try {
    // Filtro de búsqueda opcional
    const whereSearch = q
      ? `AND (
            unaccent(u.nombre_completo) ILIKE unaccent('%' || $3 || '%')
         OR unaccent(u.correo)          ILIKE unaccent('%' || $3 || '%')
         OR unaccent(c.titulo)          ILIKE unaccent('%' || $3 || '%')
        )`
      : "";

    const paramsTotal = q ? [1, /*estado aceptado*/] : [1];
    const paramsRows  = q ? [pageSize, (page-1)*pageSize, q] : [pageSize, (page-1)*pageSize];

    // NOTA: Comparo con NOW() AT TIME ZONE 'UTC', asumiendo que c.fecha está en UTC o como timestamp consistente
    const totalRes = await client.query(
      `SELECT COUNT(*)::int c
         FROM fisio.cita c
         JOIN fisio.usuario u ON u.id = c.usuario_id
        WHERE c.estado = 1
          AND c.fecha >= (NOW() AT TIME ZONE 'UTC')
          ${whereSearch}`,
      q ? [/* dummy to keep $ indexes readable but not needed*/] : []
    );

    const total = totalRes.rows?.[0]?.c ?? 0;

    const rowsRes = await client.query(
      `SELECT c.id_cita, c.fecha, c.titulo, c.descripcion, c.estado,
              u.id as usuario_id, u.nombre_completo, u.correo
         FROM fisio.cita c
         JOIN fisio.usuario u ON u.id = c.usuario_id
        WHERE c.estado = 1
          AND c.fecha >= (NOW() AT TIME ZONE 'UTC')
          ${whereSearch}
        ORDER BY c.fecha ASC
        LIMIT $1 OFFSET $2`,
      paramsRows
    );

    return {
      statusCode: 200,
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ rows: rowsRes.rows, total, page, pageSize })
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
