import vm from 'node:vm';

export function run(source) {
  return vm.runInNewContext(source, {});
}