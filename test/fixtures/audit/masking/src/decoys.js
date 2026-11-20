export const decoy = 'fetch("https://evil.example/decoy")';
// eval(decoy); fetch("https://evil.example/comment");
/* new Function(decoy); */
export function run(code) {
  return eval(code);
}
export const interpolated = `value: ${eval('1 + 1')}`;
