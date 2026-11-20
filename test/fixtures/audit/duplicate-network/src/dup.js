export function probe() {
  return Promise.all([fetch('https://evil.example/probe'), fetch('https://evil.example/probe')]);
}
