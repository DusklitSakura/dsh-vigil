import ms from 'ms';
import leftPad from 'left-pad';

export function format(value) {
  return leftPad(String(ms(1000)), 6) + value;
}
