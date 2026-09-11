// ============================================================
// FUNLEARN API WORKER
// Cloudflare Pages Functions + D1
// ============================================================

const SESSION_DAYS = 30;
const MIN_PASSWORD_LENGTH = 10;
const USERNAME_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{2,31}$/;

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

function errorDetail(err) {
  return String(err?.message || err || "Unknown error").slice(0, 1500);
}

// ============================================================
// CRYPTO
// ============================================================

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
    String(s || "")
      .replace(/-/g, "+")
      .replace(/_/g, "/") +
    "===".slice((String(s || "").length + 3) % 4);

  return Uint8Array.from(atob(p), c => c.charCodeAt(0));
}

async function digest(bytes) {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytes)
  );
}

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

  return `pbkdf2_sha256$${iterations}$${b64(
    salt
  )}$${b64(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split("$");

    if (parts.length !== 4) {
      return false;
    }

    if (parts[0] !== "pbkdf2_sha256") {
      return false;
    }

    const iterations = Number(parts[1]);

    if (!Number.isFinite(iterations) || iterations < 1) {
      return false;
    }

    const actual = await passwordHash(
      password,
      unb64(parts[2]),
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

async function hashToken(token) {
  return b64(
    await digest(
      new TextEncoder().encode(token)
    )
  );
}

// ============================================================
// COOKIE
// ============================================================

function cookie(name, value, maxAge) {
  return [
    `${name}=${encodeURIComponent(value)}`,
    `Max-Age=${maxAge}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ].join("; ");
}

function clearCookie(name) {
  return [
    `${name}=`,
    "Max-Age=0",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ].join("; ");
}

function parseCookies(request) {
  const out = {};

  const raw = request.headers.get("cookie") || "";

  for (const part of raw.split(";")) {
    const i = part.indexOf("=");

    if (i <= 0) {
      continue;
    }

    const key = part.slice(0, i).trim();
    const value = part
      .slice(i + 1)
      .trim();

    try {
      out[key] = decodeURIComponent(value);
    } catch {
      out[key] = value;
    }
  }

  return out;
}

// ============================================================
// BASIC HELPERS
// ============================================================

function safeJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function normalizeUsername(value) {
  return String(value || "").trim();
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
// DATABASE CORE SCHEMA
// ============================================================

async function ensureCoreSchema(env) {
  const db = env.DB;

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      id_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `).run();

  await db.prepare(`
    CREATE INDEX IF NOT EXISTS idx_sessions_user
    ON sessions(user_id)
  `).run();

  await db.prepare(`
    CREATE INDEX IF NOT EXISTS idx_sessions_expiry
    ON sessions(expires_at)
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS user_data (
      user_id TEXT PRIMARY KEY,
      schema_version INTEGER NOT NULL DEFAULT 1,
      app_database_json TEXT NOT NULL DEFAULT '{}',
      online_data_json TEXT NOT NULL DEFAULT '{}',
      rewards_json TEXT NOT NULL DEFAULT '[]',
      updated_at TEXT NOT NULL
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS video_progress (
      user_id TEXT NOT NULL,
      module_id TEXT NOT NULL,
      video_url TEXT NOT NULL DEFAULT '',
      current_time REAL NOT NULL DEFAULT 0,
      duration REAL NOT NULL DEFAULT 0,
      progress_percentage REAL NOT NULL DEFAULT 0,
      completed INTEGER NOT NULL DEFAULT 0,
      last_watched_at TEXT,
      PRIMARY KEY(user_id, module_id)
    )
  `).run();

  await db.prepare(`
    CREATE INDEX IF NOT EXISTS idx_video_progress_user
    ON video_progress(user_id)
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS comments (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      comment TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `).run();

  await db.prepare(`
    CREATE INDEX IF NOT EXISTS idx_comments_created
    ON comments(created_at DESC)
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS comment_replies (
      id TEXT PRIMARY KEY,
      comment_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      reply TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `).run();

  await db.prepare(`
    CREATE INDEX IF NOT EXISTS idx_comment_replies_comment
    ON comment_replies(comment_id, created_at)
  `).run();
}

// ============================================================
// PUBLIC VIDEO SCHEMA
// ============================================================

async function ensureColumn(
  env,
  table,
  column,
  definition
) {
  const result = await env.DB
    .prepare(`PRAGMA table_info(${table})`)
    .all();

  const columns = result.results || [];

  if (!columns.some(c => c.name === column)) {
    await env.DB
      .prepare(
        `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
      )
      .run();
  }
}

async function ensurePublicVideoSchema(env) {
  const db = env.DB;

  // ----------------------------------------------------------
  // PUBLIC VIDEOS
  // ----------------------------------------------------------

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS public_videos (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      title TEXT NOT NULL,
      module_title TEXT NOT NULL,
      description TEXT,
      video_url TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `).run();

  await ensureColumn(
    env,
    "public_videos",
    "user_id",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_videos",
    "username",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_videos",
    "title",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_videos",
    "module_title",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_videos",
    "description",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_videos",
    "video_url",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_videos",
    "created_at",
    "TEXT"
  );

  await db.prepare(`
    CREATE INDEX IF NOT EXISTS idx_public_videos_created
    ON public_videos(created_at DESC)
  `).run();

  // ----------------------------------------------------------
  // PUBLIC VIDEO COMMENTS
  // ----------------------------------------------------------

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS public_video_comments (
      id TEXT PRIMARY KEY,
      video_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      comment TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `).run();

  await ensureColumn(
    env,
    "public_video_comments",
    "video_id",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_video_comments",
    "user_id",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_video_comments",
    "username",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_video_comments",
    "comment",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_video_comments",
    "created_at",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_video_comments",
    "updated_at",
    "TEXT"
  );

  await db.prepare(`
    CREATE INDEX IF NOT EXISTS idx_public_video_comments_video
    ON public_video_comments(video_id, created_at)
  `).run();

  // ----------------------------------------------------------
  // PUBLIC VIDEO REPLIES
  // ----------------------------------------------------------

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS public_video_replies (
      id TEXT PRIMARY KEY,
      comment_id TEXT NOT NULL,
      video_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      reply TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `).run();

  await ensureColumn(
    env,
    "public_video_replies",
    "comment_id",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_video_replies",
    "video_id",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_video_replies",
    "user_id",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_video_replies",
    "username",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_video_replies",
    "reply",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_video_replies",
    "created_at",
    "TEXT"
  );

  await ensureColumn(
    env,
    "public_video_replies",
    "updated_at",
    "TEXT"
  );

  await db.prepare(`
    CREATE INDEX IF NOT EXISTS idx_public_video_replies_comment
    ON public_video_replies(comment_id, created_at)
  `).run();

  await db.prepare(`
    CREATE INDEX IF NOT EXISTS idx_public_video_replies_video
    ON public_video_replies(video_id, created_at)
  `).run();
}

// ============================================================
// AUTH
// ============================================================

async function getUser(request, env) {
  const cookies = parseCookies(request);

  const token = cookies.funlearn_session;

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
      INNER JOIN users u
        ON u.id = s.user_id
      WHERE s.id_hash = ?
        AND s.expires_at > datetime('now')
      LIMIT 1
    `)
    .bind(sid)
    .first();

  return row || null;
}

async function createSession(
  env,
  userId,
  username
) {
  const raw = b64(randomBytes(32));

  const sessionId = await hashToken(raw);

  const expires = new Date(
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
      VALUES(?,?,?,?)
    `)
    .bind(
      sessionId,
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

// ============================================================
// STATE
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
      LIMIT 1
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

        schemaVersion:
          row.schema_version || 1
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
      currentTime:
        Number(p.current_time) || 0,

      duration:
        Number(p.duration) || 0,

      percent:
        Number(p.progress_percentage) || 0,

      completed:
        !!p.completed,

      completedDate:
        p.completed
          ? String(
              p.last_watched_at || ""
            ).slice(0, 10)
          : null,

      lastWatchedAt:
        p.last_watched_at || null,

      videoUrl:
        p.video_url || ""
    };
  }

  return state;
}

async function writeState(
  env,
  userId,
  body
) {
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
      VALUES(?,?,?,?,?,?)

      ON CONFLICT(user_id)
      DO UPDATE SET
        schema_version =
          excluded.schema_version,

        app_database_json =
          excluded.app_database_json,

        online_data_json =
          excluded.online_data_json,

        rewards_json =
          excluded.rewards_json,

        updated_at =
          excluded.updated_at
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

  const statements = [];

  for (
    const [moduleId, p] of Object.entries(modules)
      .slice(0, 5000)
  ) {
    const current =
      Math.max(
        0,
        Number(p?.currentTime) || 0
      );

    const duration =
      Math.max(
        0,
        Number(p?.duration) || 0
      );

    const percent =
      Math.min(
        100,
        Math.max(
          0,
          Number(p?.percent) || 0
        )
      );

    const completed =
      p?.completed === true
        ? 1
        : 0;

    statements.push(
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
          VALUES(?,?,?,?,?,?,?,?)

          ON CONFLICT(user_id,module_id)
          DO UPDATE SET
            video_url =
              excluded.video_url,

            current_time =
              excluded.current_time,

            duration =
              excluded.duration,

            progress_percentage =
              excluded.progress_percentage,

            completed =
              MAX(
                video_progress.completed,
                excluded.completed
              ),

            last_watched_at =
              excluded.last_watched_at
        `)
        .bind(
          userId,

          String(moduleId)
            .slice(0, 200),

          String(p?.videoUrl || "")
            .slice(0, 2000),

          current,
          duration,
          percent,
          completed,

          p?.lastWatchedAt || ts
        )
    );
  }

  if (statements.length) {
    await env.DB.batch(statements);
  }
}

// ============================================================
// MAIN HANDLER
// ============================================================

export async function onRequest(context) {
  const {
    request,
    env,
    params
  } = context;

  if (!env?.DB) {
    return json(
      {
        ok: false,
        error:
          "D1 binding DB belum dikonfigurasi."
      },
      500
    );
  }

  try {
    // --------------------------------------------------------
    // Ensure required database tables exist.
    // --------------------------------------------------------

    await ensureCoreSchema(env);

    const route =
      "/" +
      (params?.path || [])
        .map(String)
        .join("/");

    const method =
      request.method.toUpperCase();

    // --------------------------------------------------------
    // Parse JSON ONLY when a request actually contains JSON.
    // GET/HEAD/DELETE kosong tidak akan dianggap JSON error.
    // --------------------------------------------------------

    let body = {};

    if (
      method !== "GET" &&
      method !== "HEAD"
    ) {
      const contentType =
        (
          request.headers.get(
            "content-type"
          ) || ""
        ).toLowerCase();

      if (
        contentType.includes(
          "application/json"
        )
      ) {
        try {
          body = await request.json();
        } catch {
          return json(
            {
              ok: false,
              error:
                "Payload JSON tidak valid."
            },
            400
          );
        }
      } else {
        body = {};
      }
    }

    // ========================================================
    // REGISTER
    // POST /api/register
    // ========================================================

    if (
      route === "/register" &&
      method === "POST"
    ) {
      const username =
        normalizeUsername(
          body.username
        );

      const password =
        String(body.password || "");

      if (
        !USERNAME_RE.test(username)
      ) {
        return json(
          {
            ok: false,
            error:
              "Username tidak valid. Gunakan 3-32 karakter: huruf, angka, _, titik, atau -."
          },
          400
        );
      }

      if (
        password.length <
        MIN_PASSWORD_LENGTH
      ) {
        return json(
          {
            ok: false,
            error:
              `Password minimal ${MIN_PASSWORD_LENGTH} karakter.`
          },
          400
        );
      }

      const userId = id("usr");
      const ts = now();

      const hash =
        await passwordHash(
          password
        );

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
            VALUES(?,?,?,?,?)
          `)
          .bind(
            userId,
            username,
            hash,
            ts,
            ts
          )
          .run();
      } catch (err) {
        console.error(
          "REGISTER_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Username sudah digunakan atau gagal membuat akun.",
            detail:
              errorDetail(err)
          },
          400
        );
      }

      try {
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
            VALUES(?,?,?,?,?,?)
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
      } catch (err) {
        console.error(
          "REGISTER_USER_DATA_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Akun berhasil dibuat tetapi data awal gagal dibuat.",
            detail:
              errorDetail(err)
          },
          500
        );
      }

      return await createSession(
        env,
        userId,
        username
      );
    }

    // ========================================================
    // LOGIN
    // ========================================================

    if (
      route === "/login" &&
      method === "POST"
    ) {
      const username =
        normalizeUsername(
          body.username
        );

      const password =
        String(body.password || "");

      const row =
        await env.DB
          .prepare(`
            SELECT
              id,
              username,
              password_hash
            FROM users
            WHERE username = ?
              COLLATE NOCASE
            LIMIT 1
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
            ok: false,
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

    // ========================================================
    // LOGOUT
    // ========================================================

    if (
      route === "/logout" &&
      method === "POST"
    ) {
      const cookies =
        parseCookies(request);

      const token =
        cookies.funlearn_session;

      if (token) {
        const sid =
          await hashToken(token);

        await env.DB
          .prepare(`
            DELETE FROM sessions
            WHERE id_hash = ?
          `)
          .bind(sid)
          .run();
      }

      return json(
        {
          ok: true
        },
        200,
        {
          "set-cookie":
            clearCookie(
              "funlearn_session"
            )
        }
      );
    }

    // ========================================================
    // CURRENT USER
    // ========================================================

    const user =
      await getUser(
        request,
        env
      );

    // ========================================================
    // PUBLIC VIDEO
    // ========================================================

    // --------------------------------------------------------
    // GET /api/public-videos
    // --------------------------------------------------------

    if (
      route === "/public-videos" &&
      method === "GET"
    ) {
      try {
        await ensurePublicVideoSchema(
          env
        );

        const result =
          await env.DB
            .prepare(`
              SELECT
                id,
                user_id AS userId,
                username,
                title,
                module_title AS moduleTitle,
                description,
                video_url AS videoUrl,
                created_at AS createdAt
              FROM public_videos
              ORDER BY created_at DESC
              LIMIT 500
            `)
            .all();

        return json({
          ok: true,
          videos:
            result.results || []
        });
      } catch (err) {
        console.error(
          "PUBLIC_VIDEO_LIST_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal mengambil daftar Public Video.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // --------------------------------------------------------
    // POST /api/public-videos
    //
    // Frontend harus mengirim:
    //
    // {
    //   title,
    //   moduleTitle,
    //   description,
    //   videoUrl
    // }
    //
    // File video TIDAK dikirim ke endpoint ini.
    // File diupload ke Top4Top oleh frontend.
    // URL hasil upload kemudian disimpan di D1.
    // --------------------------------------------------------

    if (
      route === "/public-videos" &&
      method === "POST"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Kamu harus login terlebih dahulu."
          },
          401
        );
      }

      const title =
        String(
          body.title || ""
        ).trim();

      const moduleTitle =
        String(
          body.moduleTitle || ""
        ).trim();

      const description =
        String(
          body.description || ""
        ).trim();

      const videoUrl =
        String(
          body.videoUrl || ""
        ).trim();

      // ------------------------------------------------------
      // VALIDATION
      // ------------------------------------------------------

      if (
        !title ||
        !moduleTitle ||
        !videoUrl
      ) {
        return json(
          {
            ok: false,
            error:
              "Judul video, judul modul, dan URL video wajib diisi."
          },
          400
        );
      }

      if (title.length > 160) {
        return json(
          {
            ok: false,
            error:
              "Judul video maksimal 160 karakter."
          },
          400
        );
      }

      if (
        moduleTitle.length > 100
      ) {
        return json(
          {
            ok: false,
            error:
              "Judul modul maksimal 100 karakter."
          },
          400
        );
      }

      if (
        description.length > 600
      ) {
        return json(
          {
            ok: false,
            error:
              "Deskripsi maksimal 600 karakter."
          },
          400
        );
      }

      if (
        videoUrl.length > 2000
      ) {
        return json(
          {
            ok: false,
            error:
              "URL video terlalu panjang."
          },
          400
        );
      }

      if (
        !/^https:\/\//i.test(
          videoUrl
        )
      ) {
        return json(
          {
            ok: false,
            error:
              "URL video tidak valid."
          },
          400
        );
      }

      // ------------------------------------------------------
      // SAVE TO D1
      // ------------------------------------------------------

      try {
        await ensurePublicVideoSchema(
          env
        );

        const videoId =
          id("pvideo");

        const timestamp =
          now();

        const insert =
          await env.DB
            .prepare(`
              INSERT INTO public_videos (
                id,
                user_id,
                username,
                title,
                module_title,
                description,
                video_url,
                created_at
              )
              VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
              )
            `)
            .bind(
              String(videoId),
              String(user.id),
              String(user.username),
              title,
              moduleTitle,
              description,
              videoUrl,
              timestamp
            )
            .run();

        if (
          insert &&
          insert.success === false
        ) {
          throw new Error(
            "Cloudflare D1 mengembalikan success=false ketika INSERT public_videos."
          );
        }

        // Verify immediately that the row actually exists.
        const saved =
          await env.DB
            .prepare(`
              SELECT
                id,
                user_id AS userId,
                username,
                title,
                module_title AS moduleTitle,
                description,
                video_url AS videoUrl,
                created_at AS createdAt
              FROM public_videos
              WHERE id = ?
              LIMIT 1
            `)
            .bind(videoId)
            .first();

        if (!saved) {
          throw new Error(
            "INSERT selesai tetapi metadata Public Video tidak ditemukan saat verifikasi D1."
          );
        }

        return json(
          {
            ok: true,
            video: saved
          },
          201
        );
      } catch (err) {
        console.error(
          "PUBLIC_VIDEO_SAVE_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal menyimpan metadata Public Video ke D1.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // --------------------------------------------------------
    // DELETE /api/public-videos/:videoId
    // --------------------------------------------------------

    const publicVideoMatch =
      route.match(
        /^\/public-videos\/([^/]+)$/
      );

    if (
      publicVideoMatch &&
      method === "DELETE"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Kamu harus login terlebih dahulu."
          },
          401
        );
      }

      try {
        await ensurePublicVideoSchema(
          env
        );

        const videoId =
          publicVideoMatch[1];

        const video =
          await env.DB
            .prepare(`
              SELECT
                id,
                user_id
              FROM public_videos
              WHERE id = ?
              LIMIT 1
            `)
            .bind(videoId)
            .first();

        if (!video) {
          return json(
            {
              ok: false,
              error:
                "Video tidak ditemukan."
            },
            404
          );
        }

        const isOwner =
          String(video.user_id) ===
          String(user.id);

        const isDeveloper =
          String(
            user.username || ""
          ).toLowerCase() ===
          "fazmen";

        if (
          !isOwner &&
          !isDeveloper
        ) {
          return json(
            {
              ok: false,
              error:
                "Kamu tidak memiliki izin untuk menghapus video ini."
            },
            403
          );
        }

        await env.DB.batch([
          env.DB
            .prepare(`
              DELETE FROM public_video_replies
              WHERE video_id = ?
            `)
            .bind(videoId),

          env.DB
            .prepare(`
              DELETE FROM public_video_comments
              WHERE video_id = ?
            `)
            .bind(videoId),

          env.DB
            .prepare(`
              DELETE FROM public_videos
              WHERE id = ?
            `)
            .bind(videoId)
        ]);

        return json({
          ok: true,
          deleted: true,
          videoId
        });
      } catch (err) {
        console.error(
          "PUBLIC_VIDEO_DELETE_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal menghapus Public Video.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // ========================================================
    // PUBLIC VIDEO COMMENTS
    // ========================================================

    const publicVideoCommentsMatch =
      route.match(
        /^\/public-videos\/([^/]+)\/comments$/
      );

    // --------------------------------------------------------
    // GET COMMENTS
    // --------------------------------------------------------

    if (
      publicVideoCommentsMatch &&
      method === "GET"
    ) {
      try {
        await ensurePublicVideoSchema(
          env
        );

        const videoId =
          publicVideoCommentsMatch[1];

        const video =
          await env.DB
            .prepare(`
              SELECT id
              FROM public_videos
              WHERE id = ?
              LIMIT 1
            `)
            .bind(videoId)
            .first();

        if (!video) {
          return json(
            {
              ok: false,
              error:
                "Video tidak ditemukan."
            },
            404
          );
        }

        const commentsResult =
          await env.DB
            .prepare(`
              SELECT
                id,
                user_id AS userId,
                username,
                comment,
                created_at AS createdAt,
                updated_at AS updatedAt
              FROM public_video_comments
              WHERE video_id = ?
              ORDER BY created_at ASC
            `)
            .bind(videoId)
            .all();

        const repliesResult =
          await env.DB
            .prepare(`
              SELECT
                id,
                comment_id AS commentId,
                video_id AS videoId,
                user_id AS userId,
                username,
                reply,
                created_at AS createdAt,
                updated_at AS updatedAt
              FROM public_video_replies
              WHERE video_id = ?
              ORDER BY created_at ASC
            `)
            .bind(videoId)
            .all();

        const replies =
          repliesResult.results || [];

        const comments =
          (
            commentsResult.results ||
            []
          ).map(comment => ({
            ...comment,
            replies:
              replies.filter(
                reply =>
                  String(
                    reply.commentId
                  ) ===
                  String(comment.id)
              )
          }));

        return json({
          ok: true,
          comments
        });
      } catch (err) {
        console.error(
          "PUBLIC_VIDEO_COMMENTS_GET_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal mengambil komentar video.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // --------------------------------------------------------
    // POST COMMENT
    // --------------------------------------------------------

    if (
      publicVideoCommentsMatch &&
      method === "POST"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Kamu harus login terlebih dahulu."
          },
          401
        );
      }

      try {
        await ensurePublicVideoSchema(
          env
        );

        const videoId =
          publicVideoCommentsMatch[1];

        const video =
          await env.DB
            .prepare(`
              SELECT id
              FROM public_videos
              WHERE id = ?
              LIMIT 1
            `)
            .bind(videoId)
            .first();

        if (!video) {
          return json(
            {
              ok: false,
              error:
                "Video tidak ditemukan."
            },
            404
          );
        }

        const comment =
          String(
            body.comment ||
            body.text ||
            ""
          ).trim();

        if (!comment) {
          return json(
            {
              ok: false,
              error:
                "Komentar tidak boleh kosong."
            },
            400
          );
        }

        if (
          comment.length > 2000
        ) {
          return json(
            {
              ok: false,
              error:
                "Komentar maksimal 2000 karakter."
            },
            400
          );
        }

        const commentId =
          id("pvcomment");

        const timestamp =
          now();

        await env.DB
          .prepare(`
            INSERT INTO public_video_comments (
              id,
              video_id,
              user_id,
              username,
              comment,
              created_at,
              updated_at
            )
            VALUES(?,?,?,?,?,?,?)
          `)
          .bind(
            commentId,
            videoId,
            String(user.id),
            String(user.username),
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
              videoId,
              userId: user.id,
              username: user.username,
              comment,
              createdAt: timestamp,
              updatedAt: timestamp,
              replies: []
            }
          },
          201
        );
      } catch (err) {
        console.error(
          "PUBLIC_VIDEO_COMMENT_POST_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal menyimpan komentar Public Video.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // ========================================================
    // PUBLIC VIDEO REPLIES
    // ========================================================

    const publicVideoReplyMatch =
      route.match(
        /^\/public-videos\/([^/]+)\/comments\/([^/]+)\/replies$/
      );

    // --------------------------------------------------------
    // POST REPLY
    // --------------------------------------------------------

    if (
      publicVideoReplyMatch &&
      method === "POST"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Kamu harus login terlebih dahulu."
          },
          401
        );
      }

      try {
        await ensurePublicVideoSchema(
          env
        );

        const videoId =
          publicVideoReplyMatch[1];

        const commentId =
          publicVideoReplyMatch[2];

        const parent =
          await env.DB
            .prepare(`
              SELECT id
              FROM public_video_comments
              WHERE id = ?
                AND video_id = ?
              LIMIT 1
            `)
            .bind(
              commentId,
              videoId
            )
            .first();

        if (!parent) {
          return json(
            {
              ok: false,
              error:
                "Komentar tidak ditemukan."
            },
            404
          );
        }

        const reply =
          String(
            body.reply ||
            body.comment ||
            body.text ||
            ""
          ).trim();

        if (!reply) {
          return json(
            {
              ok: false,
              error:
                "Reply tidak boleh kosong."
            },
            400
          );
        }

        if (
          reply.length > 2000
        ) {
          return json(
            {
              ok: false,
              error:
                "Reply maksimal 2000 karakter."
            },
            400
          );
        }

        const replyId =
          id("pvreply");

        const timestamp =
          now();

        await env.DB
          .prepare(`
            INSERT INTO public_video_replies (
              id,
              comment_id,
              video_id,
              user_id,
              username,
              reply,
              created_at,
              updated_at
            )
            VALUES(?,?,?,?,?,?,?,?)
          `)
          .bind(
            replyId,
            commentId,
            videoId,
            String(user.id),
            String(user.username),
            reply,
            timestamp,
            timestamp
          )
          .run();

        return json(
          {
            ok: true,
            reply: {
              id: replyId,
              commentId,
              videoId,
              userId: user.id,
              username: user.username,
              reply,
              createdAt: timestamp,
              updatedAt: timestamp
            }
          },
          201
        );
      } catch (err) {
        console.error(
          "PUBLIC_VIDEO_REPLY_POST_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal menyimpan reply Public Video.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // --------------------------------------------------------
    // DELETE PUBLIC VIDEO COMMENT
    // --------------------------------------------------------

    const publicVideoCommentDeleteMatch =
      route.match(
        /^\/public-videos\/([^/]+)\/comments\/([^/]+)$/
      );

    if (
      publicVideoCommentDeleteMatch &&
      method === "DELETE"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Kamu harus login terlebih dahulu."
          },
          401
        );
      }

      try {
        await ensurePublicVideoSchema(
          env
        );

        const videoId =
          publicVideoCommentDeleteMatch[1];

        const commentId =
          publicVideoCommentDeleteMatch[2];

        const comment =
          await env.DB
            .prepare(`
              SELECT
                id,
                user_id
              FROM public_video_comments
              WHERE id = ?
                AND video_id = ?
              LIMIT 1
            `)
            .bind(
              commentId,
              videoId
            )
            .first();

        if (!comment) {
          return json(
            {
              ok: false,
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
          String(
            user.username || ""
          ).toLowerCase() ===
          "fazmen";

        if (
          !isOwner &&
          !isDeveloper
        ) {
          return json(
            {
              ok: false,
              error:
                "Kamu tidak memiliki izin untuk menghapus komentar ini."
            },
            403
          );
        }

        await env.DB.batch([
          env.DB
            .prepare(`
              DELETE FROM public_video_replies
              WHERE comment_id = ?
            `)
            .bind(commentId),

          env.DB
            .prepare(`
              DELETE FROM public_video_comments
              WHERE id = ?
            `)
            .bind(commentId)
        ]);

        return json({
          ok: true,
          deleted: true,
          commentId
        });
      } catch (err) {
        console.error(
          "PUBLIC_VIDEO_COMMENT_DELETE_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal menghapus komentar Public Video.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // ========================================================
    // DELETE PUBLIC VIDEO REPLY
    // ========================================================

    const publicVideoReplyDeleteMatch =
      route.match(
        /^\/public-videos\/([^/]+)\/comments\/reply\/([^/]+)$/
      );

    if (
      publicVideoReplyDeleteMatch &&
      method === "DELETE"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Kamu harus login terlebih dahulu."
          },
          401
        );
      }

      try {
        await ensurePublicVideoSchema(
          env
        );

        const videoId =
          publicVideoReplyDeleteMatch[1];

        const replyId =
          publicVideoReplyDeleteMatch[2];

        const reply =
          await env.DB
            .prepare(`
              SELECT
                id,
                user_id
              FROM public_video_replies
              WHERE id = ?
                AND video_id = ?
              LIMIT 1
            `)
            .bind(
              replyId,
              videoId
            )
            .first();

        if (!reply) {
          return json(
            {
              ok: false,
              error:
                "Reply tidak ditemukan."
            },
            404
          );
        }

        const isOwner =
          String(reply.user_id) ===
          String(user.id);

        const isDeveloper =
          String(
            user.username || ""
          ).toLowerCase() ===
          "fazmen";

        if (
          !isOwner &&
          !isDeveloper
        ) {
          return json(
            {
              ok: false,
              error:
                "Kamu tidak memiliki izin untuk menghapus reply ini."
            },
            403
          );
        }

        await env.DB
          .prepare(`
            DELETE FROM public_video_replies
            WHERE id = ?
          `)
          .bind(replyId)
          .run();

        return json({
          ok: true,
          deleted: true,
          replyId
        });
      } catch (err) {
        console.error(
          "PUBLIC_VIDEO_REPLY_DELETE_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal menghapus reply Public Video.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // ========================================================
    // GLOBAL COMMENTS
    // ========================================================

    // --------------------------------------------------------
    // GET /api/comments
    // --------------------------------------------------------

    if (
      route === "/comments" &&
      method === "GET"
    ) {
      try {
        const result =
          await env.DB
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

        const repliesResult =
          await env.DB
            .prepare(`
              SELECT
                id,
                comment_id AS commentId,
                user_id AS userId,
                username,
                reply,
                created_at AS createdAt,
                updated_at AS updatedAt
              FROM comment_replies
              ORDER BY created_at ASC
            `)
            .all();

        const replyMap =
          new Map();

        for (
          const reply of
          repliesResult.results || []
        ) {
          if (
            !replyMap.has(
              reply.commentId
            )
          ) {
            replyMap.set(
              reply.commentId,
              []
            );
          }

          replyMap
            .get(reply.commentId)
            .push(reply);
        }

        const comments =
          (
            result.results || []
          ).map(comment => ({
            ...comment,
            replies:
              replyMap.get(
                comment.id
              ) || []
          }));

        return json({
          ok: true,
          comments
        });
      } catch (err) {
        console.error(
          "COMMENTS_GET_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal mengambil komentar.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // --------------------------------------------------------
    // POST /api/comments
    // --------------------------------------------------------

    if (
      route === "/comments" &&
      method === "POST"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Kamu harus login terlebih dahulu."
          },
          401
        );
      }

      const comment =
        String(
          body.comment || ""
        ).trim();

      if (!comment) {
        return json(
          {
            ok: false,
            error:
              "Komentar tidak boleh kosong."
          },
          400
        );
      }

      if (
        comment.length > 2000
      ) {
        return json(
          {
            ok: false,
            error:
              "Komentar maksimal 2000 karakter."
          },
          400
        );
      }

      try {
        const commentId =
          id("comment");

        const timestamp =
          now();

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
            VALUES(?,?,?,?,?,?)
          `)
          .bind(
            commentId,
            String(user.id),
            String(user.username),
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
              updatedAt: timestamp,
              replies: []
            }
          },
          201
        );
      } catch (err) {
        console.error(
          "COMMENTS_POST_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal menyimpan komentar.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // --------------------------------------------------------
    // POST /api/comments/:id/replies
    // --------------------------------------------------------

    const globalReplyMatch =
      route.match(
        /^\/comments\/([^/]+)\/replies$/
      );

    if (
      globalReplyMatch &&
      method === "POST"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Kamu harus login terlebih dahulu."
          },
          401
        );
      }

      const commentId =
        globalReplyMatch[1];

      const parent =
        await env.DB
          .prepare(`
            SELECT id
            FROM comments
            WHERE id = ?
            LIMIT 1
          `)
          .bind(commentId)
          .first();

      if (!parent) {
        return json(
          {
            ok: false,
            error:
              "Komentar tidak ditemukan."
          },
          404
        );
      }

      const reply =
        String(
          body.reply || ""
        ).trim();

      if (!reply) {
        return json(
          {
            ok: false,
            error:
              "Balasan tidak boleh kosong."
          },
          400
        );
      }

      if (
        reply.length > 2000
      ) {
        return json(
          {
            ok: false,
            error:
              "Balasan maksimal 2000 karakter."
          },
          400
        );
      }

      try {
        const replyId =
          id("reply");

        const timestamp =
          now();

        await env.DB
          .prepare(`
            INSERT INTO comment_replies(
              id,
              comment_id,
              user_id,
              username,
              reply,
              created_at,
              updated_at
            )
            VALUES(?,?,?,?,?,?,?)
          `)
          .bind(
            replyId,
            commentId,
            String(user.id),
            String(user.username),
            reply,
            timestamp,
            timestamp
          )
          .run();

        return json(
          {
            ok: true,
            reply: {
              id: replyId,
              commentId,
              userId: user.id,
              username: user.username,
              reply,
              createdAt: timestamp,
              updatedAt: timestamp
            }
          },
          201
        );
      } catch (err) {
        console.error(
          "GLOBAL_REPLY_POST_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal menyimpan balasan.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // --------------------------------------------------------
    // DELETE /api/comments/reply/:id
    // --------------------------------------------------------

    const globalReplyDeleteMatch =
      route.match(
        /^\/comments\/reply\/([^/]+)$/
      );

    if (
      globalReplyDeleteMatch &&
      method === "DELETE"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Kamu harus login terlebih dahulu."
          },
          401
        );
      }

      const replyId =
        globalReplyDeleteMatch[1];

      const reply =
        await env.DB
          .prepare(`
            SELECT
              id,
              user_id
            FROM comment_replies
            WHERE id = ?
            LIMIT 1
          `)
          .bind(replyId)
          .first();

      if (!reply) {
        return json(
          {
            ok: false,
            error:
              "Balasan tidak ditemukan."
          },
          404
        );
      }

      const isOwner =
        String(reply.user_id) ===
        String(user.id);

      const isDeveloper =
        String(
          user.username || ""
        ).toLowerCase() ===
        "fazmen";

      if (
        !isOwner &&
        !isDeveloper
      ) {
        return json(
          {
            ok: false,
            error:
              "Kamu tidak memiliki izin untuk menghapus balasan ini."
          },
          403
        );
      }

      await env.DB
        .prepare(`
          DELETE FROM comment_replies
          WHERE id = ?
        `)
        .bind(replyId)
        .run();

      return json({
        ok: true,
        deleted: true,
        replyId
      });
    }

    // --------------------------------------------------------
    // DELETE /api/comments/:id
    // --------------------------------------------------------

    const globalCommentDeleteMatch =
      route.match(
        /^\/comments\/([^/]+)$/
      );

    if (
      globalCommentDeleteMatch &&
      method === "DELETE"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Kamu harus login terlebih dahulu."
          },
          401
        );
      }

      const commentId =
        globalCommentDeleteMatch[1];

      const comment =
        await env.DB
          .prepare(`
            SELECT
              id,
              user_id
            FROM comments
            WHERE id = ?
            LIMIT 1
          `)
          .bind(commentId)
          .first();

      if (!comment) {
        return json(
          {
            ok: false,
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
        String(
          user.username || ""
        ).toLowerCase() ===
        "fazmen";

      if (
        !isOwner &&
        !isDeveloper
      ) {
        return json(
          {
            ok: false,
            error:
              "Kamu tidak memiliki izin untuk menghapus komentar ini."
          },
          403
        );
      }

      await env.DB.batch([
        env.DB
          .prepare(`
            DELETE FROM comment_replies
            WHERE comment_id = ?
          `)
          .bind(commentId),

        env.DB
          .prepare(`
            DELETE FROM comments
            WHERE id = ?
          `)
          .bind(commentId)
      ]);

      return json({
        ok: true,
        deleted: true,
        commentId
      });
    }

    // ========================================================
    // DELETE ACCOUNT
    // ========================================================

    if (
      route === "/delete-account" &&
      method === "POST"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Sesi tidak valid."
          },
          401,
          {
            "set-cookie":
              clearCookie(
                "funlearn_session"
              )
          }
        );
      }

      if (
        String(
          body.confirm || ""
        )
          .trim()
          .toLowerCase() !==
        "hapus"
      ) {
        return json(
          {
            ok: false,
            error:
              'Ketik "hapus" untuk mengonfirmasi.'
          },
          400
        );
      }

      try {
        await ensurePublicVideoSchema(
          env
        );

        // Ambil video milik user terlebih dahulu.
        const ownedVideos =
          await env.DB
            .prepare(`
              SELECT id
              FROM public_videos
              WHERE user_id = ?
            `)
            .bind(user.id)
            .all();

        const videoIds =
          (
            ownedVideos.results || []
          ).map(row => row.id);

        const statements = [];

        // Hapus replies milik user.
        statements.push(
          env.DB
            .prepare(`
              DELETE FROM comment_replies
              WHERE user_id = ?
            `)
            .bind(user.id)
        );

        // Hapus global comments milik user.
        statements.push(
          env.DB
            .prepare(`
              DELETE FROM comments
              WHERE user_id = ?
            `)
            .bind(user.id)
        );

        // Hapus progress.
        statements.push(
          env.DB
            .prepare(`
              DELETE FROM video_progress
              WHERE user_id = ?
            `)
            .bind(user.id)
        );

        // Hapus state.
        statements.push(
          env.DB
            .prepare(`
              DELETE FROM user_data
              WHERE user_id = ?
            `)
            .bind(user.id)
        );

        // Hapus Public Video replies/comments/video.
        for (
          const videoId of videoIds
        ) {
          statements.push(
            env.DB
              .prepare(`
                DELETE FROM public_video_replies
                WHERE video_id = ?
              `)
              .bind(videoId)
          );

          statements.push(
            env.DB
              .prepare(`
                DELETE FROM public_video_comments
                WHERE video_id = ?
              `)
              .bind(videoId)
          );

          statements.push(
            env.DB
              .prepare(`
                DELETE FROM public_videos
                WHERE id = ?
              `)
              .bind(videoId)
          );
        }

        // Hapus komentar/reply Public Video milik user
        // walaupun bukan uploader video.
        statements.push(
          env.DB
            .prepare(`
              DELETE FROM public_video_replies
              WHERE user_id = ?
            `)
            .bind(user.id)
        );

        statements.push(
          env.DB
            .prepare(`
              DELETE FROM public_video_comments
              WHERE user_id = ?
            `)
            .bind(user.id)
        );

        // Hapus session.
        statements.push(
          env.DB
            .prepare(`
              DELETE FROM sessions
              WHERE user_id = ?
            `)
            .bind(user.id)
        );

        // Terakhir hapus user.
        statements.push(
          env.DB
            .prepare(`
              DELETE FROM users
              WHERE id = ?
            `)
            .bind(user.id)
        );

        await env.DB.batch(
          statements
        );

        return json(
          {
            ok: true,
            deleted: true
          },
          200,
          {
            "set-cookie":
              clearCookie(
                "funlearn_session"
              )
          }
        );
      } catch (err) {
        console.error(
          "DELETE_ACCOUNT_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal menghapus akun.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // ========================================================
    // ME
    // ========================================================

    if (
      route === "/me" &&
      method === "GET"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            user: null
          },
          401
        );
      }

      try {
        const state =
          await readState(
            env,
            user.id
          );

        return json({
          ok: true,
          user,
          state
        });
      } catch (err) {
        console.error(
          "ME_STATE_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal mengambil data akun.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // ========================================================
    // SYNC
    // ========================================================

    if (
      route === "/sync" &&
      method === "POST"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Sesi tidak valid."
          },
          401
        );
      }

      try {
        await writeState(
          env,
          user.id,
          body
        );

        return json({
          ok: true,
          syncedAt: now()
        });
      } catch (err) {
        console.error(
          "SYNC_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal menyinkronkan data.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // ========================================================
    // PROGRESS
    // ========================================================

    if (
      route === "/progress" &&
      method === "POST"
    ) {
      if (!user) {
        return json(
          {
            ok: false,
            error:
              "Sesi tidak valid."
          },
          401
        );
      }

      const moduleId =
        String(
          body.moduleId || ""
        ).trim();

      if (!moduleId) {
        return json(
          {
            ok: false,
            error:
              "moduleId wajib diisi."
          },
          400
        );
      }

      try {
        const currentState =
          await readState(
            env,
            user.id
          );

        currentState.onlineProgress =
          currentState.onlineProgress ||
          {};

        currentState.onlineProgress[
          moduleId
        ] = body;

        await writeState(
          env,
          user.id,
          currentState
        );

        return json({
          ok: true
        });
      } catch (err) {
        console.error(
          "PROGRESS_ERROR",
          err
        );

        return json(
          {
            ok: false,
            error:
              "Gagal menyimpan progress video.",
            detail:
              errorDetail(err)
          },
          500
        );
      }
    }

    // ========================================================
    // NOT FOUND
    // ========================================================

    return json(
      {
        ok: false,
        error: "Not found"
      },
      404
    );

  } catch (err) {
    // ========================================================
    // GLOBAL ERROR HANDLER
    //
    // Ini penting supaya Cloudflare tidak mengembalikan
    // halaman HTML "Worker threw exception".
    // ========================================================

    console.error(
      "FUNLEARN_API_FATAL_ERROR",
      err
    );

    return json(
      {
        ok: false,
        error:
          "Terjadi kesalahan pada API FunLearn.",
        detail:
          errorDetail(err)
      },
      500
    );
  }
}
