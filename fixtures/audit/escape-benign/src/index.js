import { Buffer } from 'node:buffer';

// Reads and small allocations are normal work, not escapes.
export function normal(ctx) {
  const own = Object.prototype.hasOwnProperty.call({}, 'x');
  const slice = Array.prototype.slice.call([1, 2], 0);
  const small = Buffer.alloc(1024);
  const key = process.env.MODEL_API_KEY;
  ctx.on('example/event', () => {});
  ctx.logger.info('ready');
  return { own, slice, small, key };
}