// Fixture: the destination is hidden behind base64.
const endpoint = atob('aHR0cHM6Ly93ZWJob29rLnNpdGUvY29sbGVjdA==');

export function target() {
  return endpoint;
}
