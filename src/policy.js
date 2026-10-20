// House Rules: what applies to one device right now. Shield (DNS) and the Gate (firewall) both ask
// here, so a device is treated the same way by both.
//
// Household settings are the floor; a device's Crew can only add to them (more categories, Clean
// Search, extra names, bedtimes, a pause).

const mins = (hhmm) => { const [h, m] = String(hhmm).split(":").map(Number); return h * 60 + (m || 0); };

/** Is a bedtime { days:[0..6] (the day it starts; 0 = Sunday), from:"21:00", to:"07:00" } on at `now`? */
export function bedtimeOn(b, now) {
  const t = now.getHours() * 60 + now.getMinutes();
  const day = now.getDay(), yesterday = (day + 6) % 7;
  const from = mins(b.from), to = mins(b.to);
  const days = b.days || [0, 1, 2, 3, 4, 5, 6];
  if (from === to) return false;
  if (from < to) return days.includes(day) && t >= from && t < to;
  return (days.includes(day) && t >= from) || (days.includes(yesterday) && t < to);
}

/** Everything that applies to `device` (a state.devices entry, or null for a stranger). */
export function rulesFor(state, device, now = new Date()) {
  const s = state.shield;
  const crew = device?.crew ? state.crews[device.crew] : null;
  // Locked (the CelloCloud plan doesn't include Cellowalla now): no protection at all, but nobody is
  // ever cut off either. Every device gets plain, unfiltered internet.
  if (state.plan?.locked) return { shield: false, lists: [], cleanSearch: false, deny: [], allow: [], cut: null, crew: crew?.id || null, locked: true };
  const ms = now.getTime();
  const lists = Object.entries(s.lists).filter(([, on]) => on).map(([k]) => k);
  for (const c of s.custom) if (c.on) lists.push(`custom:${c.id}`);
  if (crew) for (const [k, on] of Object.entries(crew.lists || {})) if (on && !lists.includes(k)) lists.push(k);

  let cut = null; // why this device has no internet right now
  if (device?.blocked) cut = "blocked";
  else if (device?.lobby && state.lobby.on) cut = "lobby";
  else if ((device?.pausedUntil || 0) > ms) cut = "paused";
  else if ((crew?.pausedUntil || 0) > ms) cut = "paused";
  else if (crew && !((crew.graceUntil || 0) > ms) && (crew.bedtimes || []).some((b) => bedtimeOn(b, now))) cut = "bedtime";

  return {
    shield: s.on,
    lists,
    cleanSearch: s.cleanSearch || !!crew?.cleanSearch,
    deny: crew?.deny?.length ? [...s.deny, ...crew.deny] : s.deny,
    allow: s.allow,
    cut,
    crew: crew?.id || null,
  };
}
