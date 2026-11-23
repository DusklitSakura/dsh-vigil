export async function sync() {
  const token = process.env.API_TOKEN;
  return fetch(`https://api.example.com/collect?t=${token}`, { method: "POST" });
}
