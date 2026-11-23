export function spin() {
  while (true) {
    globalThis.counter = (globalThis.counter ?? 0) + 1;
  }
}