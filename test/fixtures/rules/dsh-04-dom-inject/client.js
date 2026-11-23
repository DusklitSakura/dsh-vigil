const STYLE_ID = 'dsh-vigil-fixture-dsh-04';

export function mount() {
  const banner = document.createElement('div');
  banner.id = STYLE_ID;
  banner.textContent = 'fixture';
  document.body.appendChild(banner);
}