const FEED_PATH = '/api/feed';

export async function load() {
  const token = window.localStorage.getItem('token');
  return fetch(FEED_PATH, { headers: { authorization: `Bearer ${token}` } });
}