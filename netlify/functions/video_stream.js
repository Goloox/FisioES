import { Client } from "pg";
import { requireUserClaims, readToken } from "./_auth.js";

function sniff(buf){
  if(!buf || buf.length<4) return "application/octet-stream";
  // mp4
  if (buf[0]===0x00 && buf[1]===0x00 && buf[2]===0x00) return "video/mp4";
  return "application/octet-stream";
}

async function pickFile(client, id_video){
  const sqls = [
    `SELECT archivo, content_type FROM fisio.video_archivos WHERE id_video=$1 ORDER BY created_at DESC LIMIT 1`,
    `SELECT archivo, content_type FROM fisio.video_archivo  WHERE id_video=$1 ORDER BY created_at DESC LIMIT 1`,
  ];
  for(const s of sqls){
    try{
      const r = await client.query(s, [id_video]);
      if(r.rowCount) return r.rows[0];
    }catch(e){
      if(!/relation .* does not exist/i.test(e.message)) throw e;
    }
  }
  return null;
}

export const handler = async (event) => {
  const auth = requireUserClaims(event);
  if(!auth.ok) return { statusCode:auth.statusCode, body:auth.error };

  const id_video = Number((event.queryStringParameters||{}).id || 0);
  if(!id_video) return { statusCode:400, body:"id requerido" };

  const client = new Client({ connectionString:process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try{
    // 1) si hay archivo binario, lo servimos
    const f = await pickFile(client, id_video);
    if (f){
      const raw = f.archivo;
      const buf = Buffer.isBuffer(raw) ? raw
        : (raw?.type==="Buffer" && Array.isArray(raw?.data)) ? Buffer.from(raw.data)
        : (typeof raw==="string" && raw.startsWith("\\x")) ? Buffer.from(raw.slice(2), "hex")
        : Buffer.from(raw);
      const ct = f.content_type || sniff(buf);
      return {
        statusCode:200,
        headers:{ "Content-Type":ct, "Cache-Control":"private, max-age=300", "Content-Disposition":"inline" },
        isBase64Encoded:true,
        body: buf.toString("base64")
      };
    }

    // 2) si hay URL, redirigimos (evitar loop hacia esta misma función)
    const r = await client.query(`SELECT video_url FROM fisio.video WHERE id_video=$1 LIMIT 1`, [id_video]);
    if(!r.rowCount) return { statusCode:404, body:"No existe el video" };

    const url = String(r.rows[0].video_url || "").trim();
    if(!url) return { statusCode:404, body:"Video sin archivo ni URL" };

    const selfFn = /^\/\.netlify\/functions\/video_stream/i;
    if (selfFn.test(url)) {
      // evitar redirección infinita
      return { statusCode:404, body:"El video_url apunta a video_stream. Sube un archivo o usa una URL externa." };
    }

    if (/^https?:\/\//i.test(url)) {
      return { statusCode:302, headers:{ Location: url } };
    }

    const token = readToken(event) || "";
    const sep = url.includes("?") ? "&" : "?";
    return { statusCode:302, headers:{ Location: `${url}${sep}jwt=${encodeURIComponent(token)}` } };
  }catch(e){
    return { statusCode:500, body:"Error: "+e.message };
  }finally{ try{ await client.end(); }catch{} }
};
