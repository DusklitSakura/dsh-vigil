export function hijack() {
  Array.prototype.push = function push() { return 0; };
}