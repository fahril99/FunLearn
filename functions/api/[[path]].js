const SESSION_DAYS = 30;
const USERNAME_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{2,31}$/;
const MIN_PASSWORD_LENGTH = 10;

// ============================================================
// RESPONSE HELPERS
// ============================================================

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers
    }
  });
}

function now() {
  return new Date().toISOString();
}

function id(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function randomBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

function b64(a) {
  return btoa(String.fromCharCode(...a))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function unb64(s) {
  const p =
    s.replace(/-/g, "+").replace(/_/g, "/") +
    "===".slice((s.length + 3) % 4);

  return Uint8Array.from(atob(p), c => c.charCodeAt(0));
}

async function digest(bytes) {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytes)
  );
}

// ============================================================
// PASSWORD
// ============================================================

async function passwordHash(
  password,
  salt = randomBytes(16),
  iterations = 100000
) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `pbkdf2_sha256$${iterations}$${b64(salt)}$${b64(
    new Uint8Array(bits)
  )}`;
}

async function verifyPassword(password, stored) {
  try {
    const parts = stored.split("$");

    if (parts.length !== 4) {
      return false;
    }

    const algorithm = parts[0];
    const iterations = Number(parts[1]);
    const salt = parts[2];

    if (
      algorithm !== "pbkdf2_sha256" ||
      !Number.isFinite(iterations) ||
      !salt
    ) {
      return false;
    }

    const actual = await passwordHash(
      password,
      unb64(salt),
      iterations
    );

    return timingSafeEqual(
      new TextEncoder().encode(actual),
      new TextEncoder().encode(stored)
    );
  } catch {
    return false;
  }
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let x = 0;

  for (let i = 0; i < a.length; i++) {
    x |= a[i] ^ b[i];
  }

  return x === 0;
}

// ============================================================
// SESSION / COOKIE
// ============================================================

async function hashToken(token) {
  return b64(
    await digest(
      new TextEncoder().encode(token)
    )
  );
}

function cookie(name, value, maxAge) {
  return `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookie(name) {
  return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function parseCookies(request) {
  const out = {};

  for (
    const part of (request.headers.get("cookie") || "").split(";")
  ) {
    const i = part.indexOf("=");

    if (i > 0) {
      out[part.slice(0, i).trim()] = decodeURIComponent(
        part.slice(i + 1).trim()
      );
    }
  }

  return out;
}

// ============================================================
// GENERAL HELPERS
// ============================================================

function safeJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function normalizeUsername(v) {
  return String(v || "").trim();
}

function defaultState() {
  return {
    appDatabase: null,
    onlineData: null,
    onlineProgress: {},
    rewards: [],
    onlineNotes: {},
    schemaVersion: 1
  };
}

// ============================================================
// AUTH
// ============================================================

async function getUser(request, env) {
  const token = parseCookies(request).funlearn_session;

  if (!token) {
    return null;
  }

  const sid = await hashToken(token);

  const row = await env.DB
    .prepare(`
      SELECT
        u.id,
        u.username
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.id_hash = ?
        AND s.expires_at > datetime('now')
    `)
    .bind(sid)
    .first();

  return row || null;
}

async function requireUser(request, env) {
  return await getUser(request, env);
}

// ============================================================
// USER STATE
// ============================================================

async function readState(env, userId) {
  const row = await env.DB
    .prepare(`
      SELECT
        schema_version,
        app_database_json,
        online_data_json,
        rewards_json
      FROM user_data
      WHERE user_id = ?
    `)
    .bind(userId)
    .first();

  const state = row
    ? {
        appDatabase: safeJson(
          row.app_database_json,
          null
        ),
        onlineData: safeJson(
          row.online_data_json,
          null
        ),
        onlineProgress: {},
        rewards: safeJson(
          row.rewards_json,
          []
        ),
        onlineNotes: {},
        schemaVersion: row.schema_version || 1
      }
    : defaultState();

  const progress = await env.DB
    .prepare(`
      SELECT
        module_id,
        video_url,
        current_time,
        duration,
        progress_percentage,
        completed,
        last_watched_at
      FROM video_progress
      WHERE user_id = ?
    `)
    .bind(userId)
    .all();

  for (const p of progress.results || []) {
    state.onlineProgress[p.module_id] = {
      currentTime: p.current_time,
      duration: p.duration,
      percent: p.progress_percentage,
      completed: !!p.completed,
      completedDate: p.completed
        ? (p.last_watched_at || "").slice(0, 10)
        : null,
      lastWatchedAt: p.last_watched_at,
      videoUrl: p.video_url
    };
  }

  return state;
}

async function writeState(env, userId, body) {
  const state = body || {};

  const app = JSON.stringify(
    state.appDatabase &&
      typeof state.appDatabase === "object"
      ? state.appDatabase
      : {}
  );

  const online = JSON.stringify(
    state.onlineData &&
      typeof state.onlineData === "object"
      ? state.onlineData
      : {}
  );

  const rewards = JSON.stringify(
    Array.isArray(state.rewards)
      ? state.rewards
      : []
  );

  const ts = now();

  await env.DB
    .prepare(`
      INSERT INTO user_data(
        user_id,
        schema_version,
        app_database_json,
        online_data_json,
        rewards_json,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?)

      ON CONFLICT(user_id)
      DO UPDATE SET
        schema_version = excluded.schema_version,
        app_database_json = excluded.app_database_json,
        online_data_json = excluded.online_data_json,
        rewards_json = excluded.rewards_json,
        updated_at = excluded.updated_at
    `)
    .bind(
      userId,
      1,
      app,
      online,
      rewards,
      ts
    )
    .run();

  const modules =
    state.onlineProgress &&
    typeof state.onlineProgress === "object"
      ? state.onlineProgress
      : {};

  const stmts = [];

  for (
    const [moduleId, p] of Object.entries(modules).slice(0, 5000)
  ) {
    const current = Math.max(
      0,
      Number(p.currentTime) || 0
    );

    const duration = Math.max(
      0,
      Number(p.duration) || 0
    );

    const percent = Math.min(
      100,
      Math.max(0, Number(p.percent) || 0)
    );

    const completed =
      p.completed === true ? 1 : 0;

    stmts.push(
      env.DB
        .prepare(`
          INSERT INTO video_progress(
            user_id,
            module_id,
            video_url,
            current_time,
            duration,
            progress_percentage,
            completed,
            last_watched_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)

          ON CONFLICT(user_id, module_id)
          DO UPDATE SET
            video_url = excluded.video_url,
            current_time = excluded.current_time,
            duration = excluded.duration,
            progress_percentage = excluded.progress_percentage,
            completed = MAX(
              video_progress.completed,
              excluded.completed
            ),
            last_watched_at = excluded.last_watched_at
        `)
        .bind(
          userId,
          String(moduleId).slice(0, 200),
          String(p.videoUrl || "").slice(0, 2000),
          current,
          duration,
          percent,
          completed,
          p.lastWatchedAt || ts
        )
    );
  }

  if (stmts.length) {
    await env.DB.batch(stmts);
  }
}

// ============================================================
// MAIN REQUEST HANDLER
// ============================================================

export async function onRequest(context) {
  const { request, env, params } = context;

  if (!env.DB) {
    return json(
      {
        error: "D1 binding DB belum dikonfigurasi."
      },
      500
    );
  }

  const route =
    "/" +
    (Array.isArray(params.path)
      ? params.path.join("/")
      : String(params.path || ""));

  const method = request.method.toUpperCase();

  // ==========================================================
  // REQUEST BODY
  //
  // Hanya POST / PUT / PATCH yang membaca JSON.
  // DELETE tidak membaca JSON karena DELETE komentar
  // hanya membutuhkan ID yang ada di URL.
  // ==========================================================

  let body = {};

  if (
    method === "POST" ||
    method === "PUT" ||
    method === "PATCH"
  ) {
    try {
      body = await request.json();
    } catch {
      return json(
        {
          error: "Payload JSON tidak valid."
        },
        400
      );
    }
  }

  // ==========================================================
  // REGISTER
  // ==========================================================

  if (
    route === "/register" &&
    method === "POST"
  ) {
    const username = normalizeUsername(
      body.username
    );

    const password = String(
      body.password || ""
    );

    if (
      !USERNAME_RE.test(username) ||
      password.length < MIN_PASSWORD_LENGTH
    ) {
      return json(
        {
          error:
            "Username atau password tidak memenuhi aturan."
        },
        400
      );
    }

    const ts = now();
    const userId = id("usr");
    const hash = await passwordHash(password);

    try {
      await env.DB
        .prepare(`
          INSERT INTO users(
            id,
            username,
            password_hash,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, ?, ?)
        `)
        .bind(
          userId,
          username,
          hash,
          ts,
          ts
        )
        .run();
    } catch {
      return json(
        {
          error:
            "Username atau password tidak dapat digunakan."
        },
        400
      );
    }

    await env.DB
      .prepare(`
        INSERT INTO user_data(
          user_id,
          schema_version,
          app_database_json,
          online_data_json,
          rewards_json,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `)
      .bind(
        userId,
        1,
        "{}",
        "{}",
        "[]",
        ts
      )
      .run();

    return await createSession(
      env,
      userId,
      username
    );
  }

  // ==========================================================
  // LOGIN
  // ==========================================================

  if (
    route === "/login" &&
    method === "POST"
  ) {
    const username = normalizeUsername(
      body.username
    );

    const password = String(
      body.password || ""
    );

    const row = await env.DB
      .prepare(`
        SELECT
          id,
          username,
          password_hash
        FROM users
        WHERE username = ?
        COLLATE NOCASE
      `)
      .bind(username)
      .first();

    if (
      !row ||
      !(await verifyPassword(
        password,
        row.password_hash
      ))
    ) {
      return json(
        {
          error:
            "Username atau password salah."
        },
        401
      );
    }

    return await createSession(
      env,
      row.id,
      row.username
    );
  }

  // ==========================================================
  // LOGOUT
  // ==========================================================

  if (
    route === "/logout" &&
    method === "POST"
  ) {
    const token =
      parseCookies(request).funlearn_session;

    if (token) {
      await env.DB
        .prepare(
          "DELETE FROM sessions WHERE id_hash = ?"
        )
        .bind(await hashToken(token))
        .run();
    }

    return json(
      { ok: true },
      200,
      {
        "set-cookie":
          clearCookie("funlearn_session")
      }
    );
  }

  // ==========================================================
  // CURRENT USER
  // ==========================================================

  const user = await requireUser(
    request,
    env
  );

  // ==========================================================
  // COMMENTS
  // ==========================================================

  // ----------------------------------------------------------
  // GET /comments
  // ----------------------------------------------------------

  if (
    route === "/comments" &&
    method === "GET"
  ) {
    const result = await env.DB
      .prepare(`
        SELECT
          id,
          user_id AS userId,
          username,
          comment,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM comments
        ORDER BY created_at DESC
      `)
      .all();

    return json({
      ok: true,
      comments: result.results || []
    });
  }

  // ----------------------------------------------------------
  // POST /comments
  // ----------------------------------------------------------

  if (
    route === "/comments" &&
    method === "POST"
  ) {
    if (!user) {
      return json(
        {
          error:
            "Kamu harus login terlebih dahulu."
        },
        401
      );
    }

    const comment = String(
      body.comment || ""
    ).trim();

    if (!comment) {
      return json(
        {
          error:
            "Komentar tidak boleh kosong."
        },
        400
      );
    }

    if (comment.length > 2000) {
      return json(
        {
          error:
            "Komentar maksimal 2000 karakter."
        },
        400
      );
    }

    const commentId = id("comment");
    const timestamp = now();

    await env.DB
      .prepare(`
        INSERT INTO comments(
          id,
          user_id,
          username,
          comment,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `)
      .bind(
        commentId,
        user.id,
        user.username,
        comment,
        timestamp,
        timestamp
      )
      .run();

    return json(
      {
        ok: true,
        comment: {
          id: commentId,
          userId: user.id,
          username: user.username,
          comment,
          createdAt: timestamp,
          updatedAt: timestamp
        }
      },
      201
    );
  }

  // ----------------------------------------------------------
  // DELETE /comments/:id
  //
  // Pemilik komentar:
  //   bisa menghapus komentar sendiri
  //
  // fazmen:
  //   bisa menghapus komentar siapa pun
  // ----------------------------------------------------------

  if (
    route.startsWith("/comments/") &&
    method === "DELETE"
  ) {
    if (!user) {
      return json(
        {
          error:
            "Kamu harus login terlebih dahulu."
        },
        401
      );
    }

    const commentId = route
      .split("/")
      .slice(2)
      .join("/");

    if (!commentId) {
      return json(
        {
          error:
            "ID komentar tidak valid."
        },
        400
      );
    }

    const comment = await env.DB
      .prepare(`
        SELECT
          id,
          user_id,
          username
        FROM comments
        WHERE id = ?
      `)
      .bind(commentId)
      .first();

    if (!comment) {
      return json(
        {
          error:
            "Komentar tidak ditemukan."
        },
        404
      );
    }

    const isOwner =
      String(comment.user_id) ===
      String(user.id);

    const isDeveloper =
      String(user.username).toLowerCase() ===
      "fazmen";

    if (!isOwner && !isDeveloper) {
      return json(
        {
          error:
            "Kamu tidak memiliki izin untuk menghapus komentar ini."
        },
        403
      );
    }

    await env.DB
      .prepare(
        "DELETE FROM comments WHERE id = ?"
      )
      .bind(commentId)
      .run();

    return json({
      ok: true,
      deleted: true,
      commentId
    });
  }

  // ==========================================================
  // DELETE ACCOUNT
  // ==========================================================

  if (
    route === "/delete-account" &&
    method === "POST"
  ) {
    if (!user) {
      return json(
        {
          error: "Sesi tidak valid."
        },
        401,
        {
          "set-cookie":
            clearCookie("funlearn_session")
        }
      );
    }

    if (
      String(body.confirm || "")
        .trim()
        .toLowerCase() !== "hapus"
    ) {
      return json(
        {
          error:
            'Ketik "hapus" untuk mengonfirmasi.'
        },
        400
      );
    }

    await env.DB.batch([
      env.DB
        .prepare(
          "DELETE FROM video_progress WHERE user_id = ?"
        )
        .bind(user.id),

      env.DB
        .prepare(
          "DELETE FROM user_data WHERE user_id = ?"
        )
        .bind(user.id),

      env.DB
        .prepare(
          "DELETE FROM sessions WHERE user_id = ?"
        )
        .bind(user.id),

      env.DB
        .prepare(
          "DELETE FROM users WHERE id = ?"
        )
        .bind(user.id)
    ]);

    return json(
      {
        ok: true,
        deleted: true
      },
      200,
      {
        "set-cookie":
          clearCookie("funlearn_session")
      }
    );
  }

  // ==========================================================
  // ME
  // ==========================================================

  if (
    route === "/me" &&
    method === "GET"
  ) {
    if (!user) {
      return json(
        {
          user: null
        },
        401
      );
    }

    return json({
      user,
      state: await readState(
        env,
        user.id
      )
    });
  }

  // ==========================================================
  // SYNC
  // ==========================================================

  if (
    route === "/sync" &&
    method === "POST"
  ) {
    if (!user) {
      return json(
        {
          error:
            "Sesi tidak valid."
        },
        401
      );
    }

    await writeState(
      env,
      user.id,
      body
    );

    return json({
      ok: true,
      syncedAt: now()
    });
  }

  // ==========================================================
  // VIDEO PROGRESS
  // ==========================================================

  if (
    route === "/progress" &&
    method === "POST"
  ) {
    if (!user) {
      return json(
        {
          error:
            "Sesi tidak valid."
        },
        401
      );
    }

    const currentState =
      await readState(
        env,
        user.id
      );

    await writeState(
      env,
      user.id,
      {
        ...currentState,
        onlineProgress: {
          ...currentState.onlineProgress,
          [String(body.moduleId)]:
            body
        }
      }
    );

    return json({
      ok: true
    });
  }

  // ==========================================================
  // NOT FOUND
  // ==========================================================

  return json(
    {
      error: "Not found"
    },
    404
  );
}

// ============================================================
// CREATE SESSION
// ============================================================

async function createSession(
  env,
  userId,
  username
) {
  const raw = b64(
    randomBytes(32)
  );

  const sid = await hashToken(raw);

  const expires =
    new Date(
      Date.now() +
        SESSION_DAYS * 86400000
    ).toISOString();

  await env.DB
    .prepare(`
      INSERT INTO sessions(
        id_hash,
        user_id,
        expires_at,
        created_at
      )
      VALUES (?, ?, ?, ?)
    `)
    .bind(
      sid,
      userId,
      expires,
      now()
    )
    .run();

  return json(
    {
      ok: true,
      user: {
        id: userId,
        username
      }
    },
    200,
    {
      "set-cookie": cookie(
        "funlearn_session",
        raw,
        SESSION_DAYS * 86400
      )
    }
  );
}
