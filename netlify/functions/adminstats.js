// netlify/functions/admin_stats.js
import { Client } from "pg";

const { DATABASE_URL } = process.env;

export const handler = async () => {
  try {
    const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await client.connect();
    const q1 = await client.query('SELECT COUNT(*) FROM fisio.usuario');
    const q2 = await client.query("SELECT COUNT(*) FROM fisio.cita WHERE CAST(fecha AS date) = CURRENT_DATE");
    const q3 = await client.query('SELECT COUNT(*) FROM fisio.video');
    await client.end();
    return {
      statusCode: 200,
      body: JSON.stringify({
        usuarios: Number(q1.rows[0].count),
        citasHoy: Number(q2.rows[0].count),
        videos: Number(q3.rows[0].count),
      }),
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
