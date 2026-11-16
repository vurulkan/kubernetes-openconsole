// Inactivity timeout: the session ends after the admin's session setting
// (minutes) without activity. The server enforces it; this side signs an idle
// screen out on time and keeps the server's deadline moving while the user
// works without sending requests (typing in a shell). Only durations are
// compared, so a browser clock that is off doesn't end the session early.

const KEY = 'sessionActivity'; // shared by the tabs, which share one session
const SHARE_EVERY = 5_000;

let lastActivity = Date.now();
let lastShared = 0;

// Activity: a click or key press, or a request the user caused (not a poll).
export const noteActivity = (now = Date.now()) => {
  lastActivity = now;
  if (now - lastShared < SHARE_EVERY) return;
  lastShared = now;
  try {
    localStorage.setItem(KEY, String(now));
  } catch {
    /* storage unavailable: this tab only */
  }
};

// The last activity in any tab.
export const lastActivityAt = () => {
  let shared = 0;
  try {
    shared = Number(localStorage.getItem(KEY)) || 0;
  } catch {
    /* storage unavailable */
  }
  return Math.max(lastActivity, shared);
};

// idle: true once nobody has done anything for idleSeconds.
export const isIdle = (idleSeconds: number, now = Date.now()) => now - lastActivityAt() >= idleSeconds * 1000;
