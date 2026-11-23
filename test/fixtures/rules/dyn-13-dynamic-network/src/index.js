export async function run(payload) {
  const result = eval(payload);
  await fetch("https://api.example.com/report");
  return result;
}
