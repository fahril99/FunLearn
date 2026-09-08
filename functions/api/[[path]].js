const SESSION_DAYS = 30;
const USERNAME_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{2,31}$/;
const MIN_PASSWORD_LENGTH = 10;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
}
function now() { return new Date().toISOString(); }
function id(prefix) { return `${prefix}_${crypto.randomUUID()}`; }
function randomBytes(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
function b64(a) { return btoa(String.fromCharCode(...a)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }
function unb64(s) { const p = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4); return Uint8Array.from(atob(p), c => c.charCodeAt(0)); }
async function digest(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }
async function passwordHash(password, salt = randomBytes(16), iterations = 100000) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256);
  return `pbkdf2_sha256$${iterations}$${b64(salt)}$${b64(new Uint8Array(bits))}`;
}
async function verifyPassword(password, stored) {
  try { const [, alg, iter, salt, expected] = stored.split("_"); const raw = stored.split("$"); const actual = await passwordHash(password, unb64(raw[2]), Number(raw[1])); return timingSafeEqual(new TextEncoder().encode(actual), new TextEncoder().encode(stored)); } catch { return false; }
}
function timingSafeEqual(a, b) { if (a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a[i] ^ b[i]; return x === 0; }
async function hashToken(token) { return b64(await digest(new TextEncoder().encode(token))); }
function cookie(name, value, maxAge) { return `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`; }
function clearCookie(name) { return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`; }
function parseCookies(request) { const out = {}; for (const part of (request.headers.get("cookie") || "").split(";")) { const i = part.indexOf("="); if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } return out; }
function safeJson(value, fallback) { try { return JSON.parse(value); } catch { return fallback; } }
function normalizeUsername(v) { return String(v || "").trim(); }
function defaultState() { return { appDatabase: null, onlineData: null, onlineProgress: {}, rewards: [], onlineNotes: {}, schemaVersion: 1 }; }

async function getUser(request, env) {
  const token = parseCookies(request).funlearn_session;
  if (!token) return null;
  const sid = await hashToken(token);
  const row = await env.DB.prepare("SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=? AND s.expires_at>datetime('now')").bind(sid).first();
  return row || null;
}
async function requireUser(request, env) { const user = await getUser(request, env); return user ? user : null; }
async function readState(env, userId) {
  const row = await env.DB.prepare("SELECT schema_version,app_database_json,online_data_json,rewards_json FROM user_data WHERE user_id=?").bind(userId).first();
  const state = row ? { appDatabase: safeJson(row.app_database_json, null), onlineData: safeJson(row.online_data_json, null), onlineProgress: {}, rewards: safeJson(row.rewards_json, []), onlineNotes: {}, schemaVersion: row.schema_version || 1 } : defaultState();
  const progress = await env.DB.prepare("SELECT module_id,video_url,current_time,duration,progress_percentage,completed,last_watched_at FROM video_progress WHERE user_id=?").bind(userId).all();
  for (const p of progress.results || []) state.onlineProgress[p.module_id] = { currentTime: p.current_time, duration: p.duration, percent: p.progress_percentage, completed: !!p.completed, completedDate: p.completed ? (p.last_watched_at || "").slice(0, 10) : null, lastWatchedAt: p.last_watched_at };
  return state;
}
async function writeState(env, userId, body) {
  const state = body || {};
  const app = JSON.stringify(state.appDatabase && typeof state.appDatabase === "object" ? state.appDatabase : {});
  const online = JSON.stringify(state.onlineData && typeof state.onlineData === "object" ? state.onlineData : {});
  const rewards = JSON.stringify(Array.isArray(state.rewards) ? state.rewards : []);
  const ts = now();
  await env.DB.prepare("INSERT INTO user_data(user_id,schema_version,app_database_json,online_data_json,rewards_json,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET schema_version=excluded.schema_version,app_database_json=excluded.app_database_json,online_data_json=excluded.online_data_json,rewards_json=excluded.rewards_json,updated_at=excluded.updated_at").bind(userId, 1, app, online, rewards, ts).run();
  const modules = state.onlineProgress && typeof state.onlineProgress === "object" ? state.onlineProgress : {};
  const stmts = [];
  for (const [moduleId, p] of Object.entries(modules).slice(0, 5000)) {
    const current = Math.max(0, Number(p.currentTime) || 0), duration = Math.max(0, Number(p.duration) || 0), percent = Math.min(100, Math.max(0, Number(p.percent) || 0)), completed = p.completed === true ? 1 : 0;
    stmts.push(env.DB.prepare("INSERT INTO video_progress(user_id,module_id,video_url,current_time,duration,progress_percentage,completed,last_watched_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(user_id,module_id) DO UPDATE SET video_url=excluded.video_url,current_time=excluded.current_time,duration=excluded.duration,progress_percentage=excluded.progress_percentage,completed=MAX(video_progress.completed,excluded.completed),last_watched_at=excluded.last_watched_at").bind(userId, String(moduleId).slice(0, 200), String(p.videoUrl || "").slice(0, 2000), current, duration, percent, completed, p.lastWatchedAt || ts));
  }
  if (stmts.length) await env.DB.batch(stmts);
}

export async function onRequest(context) {
  const { request, env, params } = context;
  if (!env.DB) return json({ error: "D1 binding DB belum dikonfigurasi." }, 500);
  const route = "/" + (params.path || []).join("/");
  const method = request.method.toUpperCase();
  let body = {}; if (method !== "GET" && method !== "HEAD") { try { body = await request.json(); } catch { return json({ error: "Payload JSON tidak valid." }, 400); } }
  if (route === "/register" && method === "POST") {
    const username = normalizeUsername(body.username), password = String(body.password || "");
    if (!USERNAME_RE.test(username) || password.length < MIN_PASSWORD_LENGTH) return json({ error: "Username atau password tidak memenuhi aturan." }, 400);
    const ts = now(), userId = id("usr"), hash = await passwordHash(password);
    try { await env.DB.prepare("INSERT INTO users(id,username,password_hash,created_at,updated_at) VALUES(?,?,?,?,?)").bind(userId, username, hash, ts, ts).run(); } catch { return json({ error: "Username atau password tidak dapat digunakan." }, 400); }
    await env.DB.prepare("INSERT INTO user_data(user_id,schema_version,app_database_json,online_data_json,rewards_json,updated_at) VALUES(?,?,?,?,?,?)").bind(userId, 1, "{}", "{}", "[]", ts).run();
    return await createSession(env, userId, username);
  }
  if (route === "/login" && method === "POST") {
    const username = normalizeUsername(body.username), password = String(body.password || "");
    const row = await env.DB.prepare("SELECT id,username,password_hash FROM users WHERE username=? COLLATE NOCASE").bind(username).first();
    if (!row || !(await verifyPassword(password, row.password_hash))) return json({ error: "Username atau password salah." }, 401);
    return await createSession(env, row.id, row.username);
  }
  if (route === "/logout" && method === "POST") {
    const token = parseCookies(request).funlearn_session; if (token) await env.DB.prepare("DELETE FROM sessions WHERE id_hash=?").bind(await hashToken(token)).run();
    return json({ ok: true }, 200, { "set-cookie": clearCookie("funlearn_session") });
  }
  const user = await requireUser(request, env);
  if (route === "/me" && method === "GET") return user ? json({ user, state: await readState(env, user.id) }) : json({ user: null }, 401);
  if (route === "/sync" && method === "POST") { if (!user) return json({ error: "Sesi tidak valid." }, 401); await writeState(env, user.id, body); return json({ ok: true, syncedAt: now() }); }
  if (route === "/progress" && method === "POST") { if (!user) return json({ error: "Sesi tidak valid." }, 401); await writeState(env, user.id, { ...(await readState(env, user.id)), onlineProgress: { [String(body.moduleId)]: body } }); return json({ ok: true }); }
  return json({ error: "Not found" }, 404);
}
async function createSession(env, userId, username) { const raw = b64(randomBytes(32)), sid = await hashToken(raw), expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString(); await env.DB.prepare("INSERT INTO sessions(id_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)").bind(sid, userId, expires, now()).run(); return json({ ok: true, user: { id: userId, username } }, 200, { "set-cookie": cookie("funlearn_session", raw, SESSION_DAYS * 86400) }); }
