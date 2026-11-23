/**
 * Approval window-alert route.
 *
 *   POST /api/dsh-vigil/alert-window  { action: 'raise' | 'clear' | 'focus' }
 *
 * Capability chain (best-effort, never throws):
 *   1. Electron window control (Host runs in a desktop window process):
 *      raise = restore/show/focus + temporary always-on-top;
 *      focus = restore previous top state and bring the window forward;
 *      clear = restore the previous always-on-top state.
 *   2. Fallback on Windows: `FlashWindowEx`. `raise` flashes the taskbar button
 *      until it is cleared (or the window is focused); `focus` restores and
 *      foregrounds the DSH window with `ShowWindow` + `SetForegroundWindow`.
 *   3. Otherwise report `unavailable`; the client falls back to window.focus()
 *      and the notification click.
 *
 * @module dsh-vigil/alert-route
 */

import { createRequire } from 'node:module'
import { execFile } from 'node:child_process'

/** Authenticated browser fetch path for the approval alert window action. */
export const ALERT_WINDOW_PATH = '/api/dsh-vigil/alert-window'

/** Load Electron from the Host process; null outside the Desktop main process. */
function defaultLoadElectron() {
  try {
    return createRequire(import.meta.url)('electron')
  } catch {
    return null
  }
}

/**
 * PowerShell script that flashes/stops/foregrounds the DSH taskbar button.
 * The script is fixed text: no user input is ever interpolated into it.
 */
function buildWindowScript(action) {
  // FLASHW_CAPTION 1, FLASHW_TRAY 2, FLASHW_TIMER 4, FLASHW_TIMERNOFG 8.
  // raise: keep flashing until the window is foreground. clear: stop.
  const flags = action === 'raise' ? '(0x1 -bor 0x2 -bor 0xC)' : '0x0'
  return [
    "$ErrorActionPreference = 'SilentlyContinue'",
    'Add-Type @"',
    'using System;',
    'using System.Runtime.InteropServices;',
    'public class VigilWin32 {',
    '  [StructLayout(LayoutKind.Sequential)] public struct FLASHWINFO { public uint cbSize; public IntPtr hwnd; public uint dwFlags; public uint uCount; public uint dwTimeout; }',
    '  [DllImport("user32.dll")] public static extern bool FlashWindowEx(ref FLASHWINFO pwfi);',
    '  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);',
    '  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);',
    '}',
    '"@',
    `$flags = ${flags}`,
    "$wins = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and ($_.MainWindowTitle -match 'DeepSeek|Harness' -or $_.ProcessName -match 'DeepSeek|Harness') }",
    'foreach ($w in $wins) {',
    '  $info = New-Object VigilWin32+FLASHWINFO',
    '  $info.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($info)',
    '  $info.hwnd = $w.MainWindowHandle',
    '  $info.dwFlags = $flags',
    '  $info.uCount = 0',
    '  $info.dwTimeout = 0',
    '  [void][VigilWin32]::FlashWindowEx([ref]$info)',
    '}',
    action === 'focus'
      ? 'foreach ($w in $wins) { [void][VigilWin32]::ShowWindow($w.MainWindowHandle, 9); [void][VigilWin32]::SetForegroundWindow($w.MainWindowHandle) }'
      : '',
  ].filter(Boolean).join('\n')
}

/** @returns {Promise<boolean>} whether the window script ran successfully */
function defaultWindowAction(action) {
  return new Promise(resolve => {
    try {
      execFile(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', buildWindowScript(action)],
        { timeout: 8000, windowsHide: true },
        error => resolve(!error),
      )
    } catch {
      resolve(false)
    }
  })
}

/**
 * Report how the Host can draw attention to the window right now.
 * @param {() => any} [loadElectron]
 * @param {NodeJS.Platform} [platform]
 * @returns {{ mode: 'electron'|'flash'|'unavailable', windows: number }}
 */
export function probeAlertWindow(loadElectron = defaultLoadElectron, platform = process.platform) {
  try {
    const electron = loadElectron()
    const browserWindow = electron?.BrowserWindow
    const windows = typeof browserWindow?.getAllWindows === 'function'
      ? browserWindow.getAllWindows().filter(win => win && (typeof win.isDestroyed !== 'function' || !win.isDestroyed()))
      : []
    if (windows.length > 0) return { mode: 'electron', windows: windows.length }
  } catch {
    // fall through to the platform fallback
  }
  return platform === 'win32' ? { mode: 'flash', windows: 0 } : { mode: 'unavailable', windows: 0 }
}

/**
 * @param {{ loadElectron?: () => any, platform?: NodeJS.Platform, windowAction?: (action: 'raise'|'clear'|'focus') => Promise<boolean> }} [deps]
 * @returns {{ path: string, methods: string[], requestBody: 'buffered', fetch: (request: Request) => Promise<Response> }}
 */
export function createAlertWindowRoute(deps = {}) {
  const loadElectron = deps.loadElectron ?? defaultLoadElectron
  const platform = deps.platform ?? process.platform
  const windowAction = deps.windowAction ?? defaultWindowAction
  /** Windows whose always-on-top state we changed, with the previous value. */
  const raised = new Map()

  const json = (payload, status = 200) => new Response(`${JSON.stringify(payload)}\n`, {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  })

  const restoreTop = () => {
    for (const [win, previous] of raised) {
      try {
        win.setAlwaysOnTop(previous)
      } catch {
        // window already gone
      }
    }
    raised.clear()
  }

  return {
    path: ALERT_WINDOW_PATH,
    methods: ['POST'],
    requestBody: 'buffered',
    fetch: async request => {
      let body = null
      try {
        body = typeof request?.json === 'function' ? await request.json().catch(() => null) : null
      } catch {
        body = null
      }
      const action = body?.action === 'clear' ? 'clear' : body?.action === 'focus' ? 'focus' : 'raise'

      let windows = []
      try {
        const electron = loadElectron()
        const browserWindow = electron?.BrowserWindow
        windows = typeof browserWindow?.getAllWindows === 'function'
          ? browserWindow.getAllWindows().filter(win => win && (typeof win.isDestroyed !== 'function' || !win.isDestroyed()))
          : []
      } catch {
        windows = []
      }

      if (windows.length > 0) {
        if (action === 'clear') {
          restoreTop()
          return json({ ok: true, mode: 'electron', action, windows: windows.length })
        }
        if (action === 'focus') restoreTop()
        for (const win of windows) {
          try {
            if (typeof win.isMinimized === 'function' && win.isMinimized()) win.restore()
            if (typeof win.show === 'function') win.show()
            if (typeof win.focus === 'function') win.focus()
            if (action === 'raise' && typeof win.setAlwaysOnTop === 'function' && !raised.has(win)) {
              const previous = typeof win.isAlwaysOnTop === 'function' ? Boolean(win.isAlwaysOnTop()) : false
              raised.set(win, previous)
              if (!previous) win.setAlwaysOnTop(true, 'floating')
            }
          } catch {
            // best-effort per window
          }
        }
        return json({ ok: true, mode: 'electron', action, windows: windows.length })
      }

      if (platform === 'win32') {
        const ok = await windowAction(action)
        return json({ ok, mode: 'flash', action })
      }

      return json({ ok: false, mode: 'unavailable', action })
    },
  }
}
