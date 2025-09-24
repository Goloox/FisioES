export const handler = async () => {
  return {
    statusCode: 200,
    headers: { 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify({ ok: true, ts: Date.now() })
  };
};
