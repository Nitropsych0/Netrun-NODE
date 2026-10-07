"use strict";

// Audit RES-11 — ONE in-process lock around every change of the 3proxy
// process table the agent makes on its own: the supervisor's respawn, the
// duplicate reaper (hygiene.js), a /deprovision kill+unlink / kill+respawn and
// an /egress_mode restart. Without it the supervisor could see a batch that
// /deprovision has just killed (and is about to unlink) as "died" and start it
// again, or act on a process snapshot the reaper is changing under it.
// /generate takes it once, right after the generation lock, so a respawn that
// started before the lock finishes first and the generation's own process
// snapshot (kill-on-rebind) sees it; the supervisor checks the generation lock
// while holding this one, so none starts after.
//
// A promise chain: FIFO, never re-entrant (do not nest withProcessLock calls).

let tail = Promise.resolve();
let depth = 0;

function withProcessLock(fn) {
  const run = tail.then(async () => {
    depth += 1;
    try {
      return await fn();
    } finally {
      depth -= 1;
    }
  });
  tail = run.catch(() => {});
  return run;
}

function isLocked() {
  return depth > 0;
}

module.exports = { withProcessLock, isLocked };
