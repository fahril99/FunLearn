const SESSION_DAYS = 30;
const USERNAME_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{2,31}$/;
const MIN_PASSWORD_LENGTH = 10;

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

// Cloudflare Workers WebCrypto supports PBKDF2 up to 100,000 iterations.
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
    const raw = stored.split("$");

    const actual = await passwordHash(
      password,
      unb64(raw[2]),
      Number(raw[1])
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
  if (a.length !== b.length) return false;

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

function cookie(name, value, maxAge) {
  return `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookie(name) {
  return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function parseCookies(request) {
  const out = {};

  for (
    const part of
    (request.headers.get("cookie") || "").split(";")
  ) {
    const i = part.indexOf("=");

    if (i > 0) {
      out[part.slice(0, i).trim()] =
        decodeURIComponent(
          part.slice(i + 1).trim()
        );
    }
  }

  return out;
}

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


/* =========================================================
   AUTH
========================================================= */

async function getUser(request, env) {
  const token =
    parseCookies(request).funlearn_session;

  if (!token) return null;

  const sid =
    await hashToken(token);

  const row =
    await env.DB.prepare(`
      SELECT
        u.id,
        u.username
      FROM sessions s
      JOIN users u
        ON u.id = s.user_id
      WHERE
        s.id_hash=?
        AND s.expires_at>datetime('now')
    `)
      .bind(sid)
      .first();

  return row || null;
}

async function requireUser(request, env) {
  const user =
    await getUser(request, env);

  return user ? user : null;
}


/* =========================================================
   USER STATE
========================================================= */

async function readState(env, userId) {
  const row =
    await env.DB.prepare(`
      SELECT
        schema_version,
        app_database_json,
        online_data_json,
        rewards_json
      FROM user_data
      WHERE user_id=?
    `)
      .bind(userId)
      .first();

  const state = row
    ? {
        appDatabase:
          safeJson(
            row.app_database_json,
            null
          ),

        onlineData:
          safeJson(
            row.online_data_json,
            null
          ),

        onlineProgress: {},

        rewards:
          safeJson(
            row.rewards_json,
            []
          ),

        onlineNotes: {},

        schemaVersion:
          row.schema_version || 1
      }
    : defaultState();

  const progress =
    await env.DB.prepare(`
      SELECT
        module_id,
        video_url,
        current_time,
        duration,
        progress_percentage,
        completed,
        last_watched_at
      FROM video_progress
      WHERE user_id=?
    `)
      .bind(userId)
      .all();

  for (
    const p of
    progress.results || []
  ) {
    state.onlineProgress[p.module_id] = {
      currentTime: p.current_time,
      duration: p.duration,
      percent: p.progress_percentage,
      completed: !!p.completed,

      completedDate:
        p.completed
          ? (p.last_watched_at || "").slice(0, 10)
          : null,

      lastWatchedAt:
        p.last_watched_at
    };
  }

  return state;
}

async function writeState(env, userId, body) {
  const state = body || {};

  const app =
    JSON.stringify(
      state.appDatabase &&
      typeof state.appDatabase === "object"
        ? state.appDatabase
        : {}
    );

  const online =
    JSON.stringify(
      state.onlineData &&
      typeof state.onlineData === "object"
        ? state.onlineData
        : {}
    );

  const rewards =
    JSON.stringify(
      Array.isArray(state.rewards)
        ? state.rewards
        : []
    );

  const ts = now();

  await env.DB.prepare(`
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
      schema_version=excluded.schema_version,
      app_database_json=excluded.app_database_json,
      online_data_json=excluded.online_data_json,
      rewards_json=excluded.rewards_json,
      updated_at=excluded.updated_at
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
    const [moduleId, p]
    of Object.entries(modules).slice(0, 5000)
  ) {
    const current =
      Math.max(
        0,
        Number(p.currentTime) || 0
      );

    const duration =
      Math.max(
        0,
        Number(p.duration) || 0
      );

    const percent =
      Math.min(
        100,
        Math.max(
          0,
          Number(p.percent) || 0
        )
      );

    const completed =
      p.completed === true
        ? 1
        : 0;

    stmts.push(
      env.DB.prepare(`
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
          video_url=excluded.video_url,
          current_time=excluded.current_time,
          duration=excluded.duration,
          progress_percentage=excluded.progress_percentage,
          completed=MAX(
            video_progress.completed,
            excluded.completed
          ),
          last_watched_at=excluded.last_watched_at
      `)
        .bind(
          userId,
          String(moduleId).slice(0, 200),
          String(
            p.videoUrl || ""
          ).slice(0, 2000),
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


/* =========================================================
   GLOBAL COMMENTS SCHEMA
========================================================= */

async function ensureReplySchema(env) {
  await env.DB.prepare(`
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

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS
    idx_comment_replies_comment
    ON comment_replies(
      comment_id,
      created_at
    )
  `).run();
}


/* =========================================================
   PUBLIC VIDEO SCHEMA
========================================================= */

async function ensureColumn(
  env,
  table,
  column,
  definition
) {
  const info =
    await env.DB
      .prepare(
        `PRAGMA table_info(${table})`
      )
      .all();

  const exists =
    (info.results || [])
      .some(
        c => c.name === column
      );

  if (!exists) {
    await env.DB
      .prepare(
        `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
      )
      .run();
  }
}

async function ensurePublicVideoSchema(env) {

  await env.DB.prepare(`
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

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS
    idx_public_videos_created
    ON public_videos(created_at DESC)
  `).run();


  await env.DB.prepare(`
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

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS
    idx_public_video_comments_video
    ON public_video_comments(
      video_id,
      created_at
    )
  `).run();


  await env.DB.prepare(`
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

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS
    idx_public_video_replies_comment
    ON public_video_replies(
      comment_id,
      created_at
    )
  `).run();
}


/* =========================================================
   MAIN REQUEST HANDLER
========================================================= */

export async function onRequest(context) {

  const {
    request,
    env,
    params
  } = context;

  if (!env.DB) {
    return json(
      {
        error:
          "D1 binding DB belum terpasang."
      },
      500
    );
  }

  const method =
    request.method.toUpperCase();

  const pathValue =
    params?.path;

  const route =
    "/" +
    (
      Array.isArray(pathValue)
        ? pathValue.join("/")
        : String(pathValue || "")
    ).replace(/^\/+/, "");

  let body = {};

  if (
    method === "POST" ||
    method === "PUT" ||
    method === "PATCH"
  ) {
    try {
      const text =
        await request.text();

      if (text.trim()) {
        body =
          JSON.parse(text);
      }
    } catch {
      return json(
        {
          error:
            "Payload JSON tidak valid."
        },
        400
      );
    }
  }

  /* =====================================================
     AUTH
  ===================================================== */

  if (
    route === "/register" &&
    method === "POST"
  ) {

    const username =
      normalizeUsername(
        body.username
      );

    const password =
      String(
        body.password || ""
      );

    if (
      !USERNAME_RE.test(username)
    ) {
      return json(
        {
          error:
            "Username tidak valid. Gunakan 3-32 karakter huruf, angka, _, titik, atau -."
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
          error:
            `Password minimal ${MIN_PASSWORD_LENGTH} karakter.`
        },
        400
      );
    }

    const existing =
      await env.DB.prepare(
        "SELECT id FROM users WHERE username=?"
      )
        .bind(username)
        .first();

    if (existing) {
      return json(
        {
          error:
            "Username sudah digunakan."
        },
        409
      );
    }

    const userId =
      id("user");

    const passwordHashValue =
      await passwordHash(password);

    await env.DB.prepare(`
      INSERT INTO users(
        id,
        username,
        password_hash,
        created_at
      )
      VALUES(?,?,?,?)
    `)
      .bind(
        userId,
        username,
        passwordHashValue,
        now()
      )
      .run();

    return await createSession(
      env,
      userId,
      username
    );
  }


  if (
    route === "/login" &&
    method === "POST"
  ) {

    const username =
      normalizeUsername(
        body.username
      );

    const password =
      String(
        body.password || ""
      );

    const row =
      await env.DB.prepare(`
        SELECT
          id,
          username,
          password_hash
        FROM users
        WHERE username=?
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


  if (
    route === "/logout" &&
    method === "POST"
  ) {

    const token =
      parseCookies(
        request
      ).funlearn_session;

    if (token) {
      await env.DB.prepare(
        "DELETE FROM sessions WHERE id_hash=?"
      )
        .bind(
          await hashToken(token)
        )
        .run();
    }

    return json(
      { ok: true },
      200,
      {
        "set-cookie":
          clearCookie(
            "funlearn_session"
          )
      }
    );
  }


  const user =
    await requireUser(
      request,
      env
    );


  /* =====================================================
     PUBLIC VIDEO
  ===================================================== */

  if (
    route === "/public-videos" &&
    method === "GET"
  ) {

    await ensurePublicVideoSchema(
      env
    );

    const result =
      await env.DB.prepare(`
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
      `).all();

    return json({
      ok: true,
      videos:
        result.results || []
    });
  }


  if (
    route === "/public-videos" &&
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

    await ensurePublicVideoSchema(
      env
    );

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

    if (
      !title ||
      !moduleTitle ||
      !videoUrl
    ) {
      return json(
        {
          error:
            "Judul video, judul modul, dan URL video wajib diisi."
        },
        400
      );
    }

    if (
      title.length > 160 ||
      moduleTitle.length > 100 ||
      description.length > 600 ||
      videoUrl.length > 2000
    ) {
      return json(
        {
          error:
            "Data video melebihi batas panjang."
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
          error:
            "URL video tidak valid."
        },
        400
      );
    }

    const videoId =
      id("pvideo");

    const ts =
      now();

    try {

      await env.DB.prepare(`
        INSERT INTO public_videos(
          id,
          user_id,
          username,
          title,
          module_title,
          description,
          video_url,
          created_at
        )
        VALUES(?,?,?,?,?,?,?,?)
      `)
        .bind(
          videoId,
          user.id,
          user.username,
          title,
          moduleTitle,
          description,
          videoUrl,
          ts
        )
        .run();

    } catch (err) {

      console.error(
        "PUBLIC_VIDEO_INSERT_ERROR",
        err
      );

      return json(
        {
          ok: false,
          error:
            "Gagal menyimpan metadata Public Video ke D1.",
          detail:
            String(
              err?.message ||
              err
            ).slice(0, 500)
        },
        500
      );
    }

    return json(
      {
        ok: true,

        video: {
          id: videoId,
          userId: user.id,
          username: user.username,
          title,
          moduleTitle,
          description,
          videoUrl,
          createdAt: ts
        }
      },
      201
    );
  }


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
          error:
            "Kamu harus login terlebih dahulu."
        },
        401
      );
    }

    await ensurePublicVideoSchema(
      env
    );

    const videoId =
      publicVideoMatch[1];

    const v =
      await env.DB.prepare(`
        SELECT
          id,
          user_id
        FROM public_videos
        WHERE id=?
      `)
        .bind(videoId)
        .first();

    if (!v) {
      return json(
        {
          error:
            "Video tidak ditemukan."
        },
        404
      );
    }

    const allowed =
      String(v.user_id) ===
        String(user.id) ||
      String(
        user.username || ""
      ).toLowerCase() ===
        "fazmen";

    if (!allowed) {
      return json(
        {
          error:
            "Kamu tidak memiliki izin untuk menghapus video ini."
        },
        403
      );
    }

    await env.DB.batch([
      env.DB.prepare(`
        DELETE FROM public_video_replies
        WHERE video_id=?
      `)
        .bind(videoId),

      env.DB.prepare(`
        DELETE FROM public_video_comments
        WHERE video_id=?
      `)
        .bind(videoId),

      env.DB.prepare(`
        DELETE FROM public_videos
        WHERE id=?
      `)
        .bind(videoId)
    ]);

    return json({
      ok: true,
      deleted: true,
      videoId
    });
  }


  /* =====================================================
     PUBLIC VIDEO COMMENTS
  ===================================================== */

  const pvc =
    route.match(
      /^\/public-videos\/([^/]+)\/comments$/
    );

  if (
    pvc &&
    method === "GET"
  ) {

    await ensurePublicVideoSchema(
      env
    );

    const videoId =
      pvc[1];

    const v =
      await env.DB.prepare(`
        SELECT id
        FROM public_videos
        WHERE id=?
      `)
        .bind(videoId)
        .first();

    if (!v) {
      return json(
        {
          error:
            "Video tidak ditemukan."
        },
        404
      );
    }

    const cr =
      await env.DB.prepare(`
        SELECT
          id,
          user_id AS userId,
          username,
          comment,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM public_video_comments
        WHERE video_id=?
        ORDER BY created_at ASC
      `)
        .bind(videoId)
        .all();

    const rr =
      await env.DB.prepare(`
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
        WHERE video_id=?
        ORDER BY created_at ASC
      `)
        .bind(videoId)
        .all();

    const replies =
      rr.results || [];

    const comments =
      (cr.results || [])
        .map(c => ({
          ...c,
          replies:
            replies.filter(
              r =>
                String(
                  r.commentId
                ) ===
                String(c.id)
            )
        }));

    return json({
      ok: true,
      comments
    });
  }


  if (
    pvc &&
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

    await ensurePublicVideoSchema(
      env
    );

    const videoId =
      pvc[1];

    const v =
      await env.DB.prepare(`
        SELECT id
        FROM public_videos
        WHERE id=?
      `)
        .bind(videoId)
        .first();

    if (!v) {
      return json(
        {
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
          error:
            "Komentar maksimal 2000 karakter."
        },
        400
      );
    }

    const commentId =
      id("pvcomment");

    const ts =
      now();

    await env.DB.prepare(`
      INSERT INTO public_video_comments(
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
        user.id,
        user.username,
        comment,
        ts,
        ts
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
          createdAt: ts,
          updatedAt: ts,
          replies: []
        }
      },
      201
    );
  }


  /* =====================================================
     PUBLIC VIDEO REPLIES
  ===================================================== */

  const pvr =
    route.match(
      /^\/public-videos\/([^/]+)\/comments\/([^/]+)\/replies$/
    );

  if (
    pvr &&
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

    await ensurePublicVideoSchema(
      env
    );

    const videoId =
      pvr[1];

    const commentId =
      pvr[2];

    const parent =
      await env.DB.prepare(`
        SELECT id
        FROM public_video_comments
        WHERE id=?
          AND video_id=?
      `)
        .bind(
          commentId,
          videoId
        )
        .first();

    if (!parent) {
      return json(
        {
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
          error:
            "Balasan maksimal 2000 karakter."
        },
        400
      );
    }

    const replyId =
      id("pvreply");

    const ts =
      now();

    await env.DB.prepare(`
      INSERT INTO public_video_replies(
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
        user.id,
        user.username,
        reply,
        ts,
        ts
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
          createdAt: ts,
          updatedAt: ts
        }
      },
      201
    );
  }


  /* =====================================================
     DELETE PUBLIC VIDEO COMMENT
  ===================================================== */

  const pvcd =
    route.match(
      /^\/public-videos\/([^/]+)\/comments\/([^/]+)$/
    );

  if (
    pvcd &&
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

    await ensurePublicVideoSchema(
      env
    );

    const videoId =
      pvcd[1];

    const commentId =
      pvcd[2];

    const c =
      await env.DB.prepare(`
        SELECT
          id,
          user_id
        FROM public_video_comments
        WHERE id=?
          AND video_id=?
      `)
        .bind(
          commentId,
          videoId
        )
        .first();

    if (!c) {
      return json(
        {
          error:
            "Komentar tidak ditemukan."
        },
        404
      );
    }

    const allowed =
      String(c.user_id) ===
        String(user.id) ||
      String(
        user.username || ""
      ).toLowerCase() ===
        "fazmen";

    if (!allowed) {
      return json(
        {
          error:
            "Kamu tidak memiliki izin untuk menghapus komentar ini."
        },
        403
      );
    }

    await env.DB.batch([
      env.DB.prepare(`
        DELETE FROM public_video_replies
        WHERE comment_id=?
      `)
        .bind(commentId),

      env.DB.prepare(`
        DELETE FROM public_video_comments
        WHERE id=?
      `)
        .bind(commentId)
    ]);

    return json({
      ok: true,
      deleted: true,
      commentId
    });
  }


  /* =====================================================
     DELETE PUBLIC VIDEO REPLY
  ===================================================== */

  const pvrd =
    route.match(
      /^\/public-videos\/([^/]+)\/comments\/reply\/([^/]+)$/
    );

  if (
    pvrd &&
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

    await ensurePublicVideoSchema(
      env
    );

    const videoId =
      pvrd[1];

    const replyId =
      pvrd[2];

    const r =
      await env.DB.prepare(`
        SELECT
          id,
          user_id
        FROM public_video_replies
        WHERE id=?
          AND video_id=?
      `)
        .bind(
          replyId,
          videoId
        )
        .first();

    if (!r) {
      return json(
        {
          error:
            "Reply tidak ditemukan."
        },
        404
      );
    }

    const allowed =
      String(r.user_id) ===
        String(user.id) ||
      String(
        user.username || ""
      ).toLowerCase() ===
        "fazmen";

    if (!allowed) {
      return json(
        {
          error:
            "Kamu tidak memiliki izin untuk menghapus reply ini."
        },
        403
      );
    }

    await env.DB.prepare(`
      DELETE FROM public_video_replies
      WHERE id=?
    `)
      .bind(replyId)
      .run();

    return json({
      ok: true,
      deleted: true,
      replyId
    });
  }


  /* =====================================================
     DELETE ACCOUNT
  ===================================================== */

  if (
    route === "/delete-account" &&
    method === "POST"
  ) {

    if (!user) {
      return json(
        {
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
          error:
            'Ketik "hapus" untuk mengonfirmasi.'
        },
        400
      );
    }

    await ensurePublicVideoSchema(
      env
    );

    await env.DB.batch([

      env.DB.prepare(`
        DELETE FROM video_progress
        WHERE user_id=?
      `)
        .bind(user.id),

      env.DB.prepare(`
        DELETE FROM user_data
        WHERE user_id=?
      `)
        .bind(user.id),

      env.DB.prepare(`
        DELETE FROM public_video_replies
        WHERE user_id=?
      `)
        .bind(user.id),

      env.DB.prepare(`
        DELETE FROM public_video_comments
        WHERE user_id=?
      `)
        .bind(user.id),

      env.DB.prepare(`
        DELETE FROM public_video_replies
        WHERE video_id IN (
          SELECT id
          FROM public_videos
          WHERE user_id=?
        )
      `)
        .bind(user.id),

      env.DB.prepare(`
        DELETE FROM public_video_comments
        WHERE video_id IN (
          SELECT id
          FROM public_videos
          WHERE user_id=?
        )
      `)
        .bind(user.id),

      env.DB.prepare(`
        DELETE FROM public_videos
        WHERE user_id=?
      `)
        .bind(user.id),

      env.DB.prepare(`
        DELETE FROM sessions
        WHERE user_id=?
      `)
        .bind(user.id),

      env.DB.prepare(`
        DELETE FROM users
        WHERE id=?
      `)
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
          clearCookie(
            "funlearn_session"
          )
      }
    );
  }


  /* =====================================================
     GLOBAL COMMENTS API
  ===================================================== */

  if (
    route === "/comments" &&
    method === "GET"
  ) {

    await ensureReplySchema(
      env
    );

    const result =
      await env.DB.prepare(`
        SELECT
          id,
          user_id AS userId,
          username,
          comment,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM comments
        ORDER BY created_at DESC
      `).all();

    const repliesResult =
      await env.DB.prepare(`
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
      `).all();

    const replyMap =
      new Map();

    for (
      const r of
      repliesResult.results || []
    ) {

      if (
        !replyMap.has(
          r.commentId
        )
      ) {
        replyMap.set(
          r.commentId,
          []
        );
      }

      replyMap
        .get(r.commentId)
        .push(r);
    }

    const comments =
      (
        result.results || []
      ).map(c => ({
        ...c,
        replies:
          replyMap.get(c.id) || []
      }));

    return json({
      ok: true,
      comments
    });
  }


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

    const comment =
      String(
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

    if (
      comment.length > 2000
    ) {
      return json(
        {
          error:
            "Komentar maksimal 2000 karakter."
        },
        400
      );
    }

    const commentId =
      id("comment");

    const timestamp =
      now();

    await env.DB.prepare(`
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
          updatedAt: timestamp,
          replies: []
        }
      },
      201
    );
  }


  /* =====================================================
     GLOBAL COMMENT REPLIES
  ===================================================== */

  if (
    route.match(
      /^\/comments\/[^/]+\/replies$/
    ) &&
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

    await ensureReplySchema(
      env
    );

    const commentId =
      route.split("/")[2];

    if (!commentId) {
      return json(
        {
          error:
            "ID komentar tidak valid."
        },
        400
      );
    }

    const parent =
      await env.DB.prepare(`
        SELECT id
        FROM comments
        WHERE id=?
      `)
        .bind(commentId)
        .first();

    if (!parent) {
      return json(
        {
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
          error:
            "Balasan maksimal 2000 karakter."
        },
        400
      );
    }

    const replyId =
      id("reply");

    const timestamp =
      now();

    await env.DB.prepare(`
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
        user.id,
        user.username,
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
  }


  /* =====================================================
     DELETE GLOBAL COMMENT REPLY
  ===================================================== */

  if (
    route.startsWith(
      "/comments/reply/"
    ) &&
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

    await ensureReplySchema(
      env
    );

    const replyId =
      route.split("/")[3];

    if (!replyId) {
      return json(
        {
          error:
            "ID balasan tidak valid."
        },
        400
      );
    }

    const row =
      await env.DB.prepare(`
        SELECT
          id,
          user_id,
          username
        FROM comment_replies
        WHERE id=?
      `)
        .bind(replyId)
        .first();

    if (!row) {
      return json(
        {
          error:
            "Balasan tidak ditemukan."
        },
        404
      );
    }

    const isOwner =
      row.user_id ===
      user.id;

    const isDeveloper =
      String(
        user.username
      ).toLowerCase() ===
      "fazmen";

    if (
      !isOwner &&
      !isDeveloper
    ) {
      return json(
        {
          error:
            "Kamu tidak memiliki izin untuk menghapus balasan ini."
        },
        403
      );
    }

    await env.DB.prepare(`
      DELETE FROM comment_replies
      WHERE id=?
    `)
      .bind(replyId)
      .run();

    return json({
      ok: true,
      deleted: true,
      replyId
    });
  }


  /* =====================================================
     DELETE GLOBAL COMMENT
  ===================================================== */

  if (
    route.startsWith(
      "/comments/"
    ) &&
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

    const commentId =
      route.split("/")[2];

    if (!commentId) {
      return json(
        {
          error:
            "ID komentar tidak valid."
        },
        400
      );
    }

    const comment =
      await env.DB.prepare(`
        SELECT
          id,
          user_id,
          username
        FROM comments
        WHERE id=?
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
      comment.user_id ===
      user.id;

    const isDeveloper =
      String(
        user.username
      ).toLowerCase() ===
      "fazmen";

    if (
      !isOwner &&
      !isDeveloper
    ) {
      return json(
        {
          error:
            "Kamu tidak memiliki izin untuk menghapus komentar ini."
        },
        403
      );
    }

    await env.DB.prepare(`
      DELETE FROM comments
      WHERE id=?
    `)
      .bind(commentId)
      .run();

    return json({
      ok: true,
      deleted: true,
      commentId
    });
  }


  /* =====================================================
     ME
  ===================================================== */

  if (
    route === "/me" &&
    method === "GET"
  ) {

    return user
      ? json({
          user,
          state:
            await readState(
              env,
              user.id
            )
        })
      : json(
          {
            user: null
          },
          401
        );
  }


  /* =====================================================
     SYNC
  ===================================================== */

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


  /* =====================================================
     ONLINE PROGRESS
  ===================================================== */

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

    await writeState(
      env,
      user.id,
      {
        ...(await readState(
          env,
          user.id
        )),

        onlineProgress: {
          [String(
            body.moduleId
          )]: body
        }
      }
    );

    return json({
      ok: true
    });
  }


  return json(
    {
      error:
        "Not found"
    },
    404
  );
}


/* =========================================================
   CREATE SESSION
========================================================= */

async function createSession(
  env,
  userId,
  username
) {

  const raw =
    b64(
      randomBytes(32)
    );

  const sid =
    await hashToken(raw);

  const expires =
    new Date(
      Date.now() +
      SESSION_DAYS *
      86400000
    ).toISOString();

  await env.DB.prepare(`
    INSERT INTO sessions(
      id_hash,
      user_id,
      expires_at,
      created_at
    )
    VALUES(?,?,?,?)
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
      "set-cookie":
        cookie(
          "funlearn_session",
          raw,
          SESSION_DAYS *
            86400
        )
    }
  );
}
