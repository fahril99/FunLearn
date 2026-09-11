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

  return `pbkdf2_sha256$${iterations}$${b64(
    salt
  )}$${b64(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  try {
    const raw = String(stored || "").split("$");

    if (raw.length !== 4) {
      return false;
    }

    if (raw[0] !== "pbkdf2_sha256") {
      return false;
    }

    const iterations = Number(raw[1]);

    if (!Number.isFinite(iterations) || iterations <= 0) {
      return false;
    }

    const actual = await passwordHash(
      password,
      unb64(raw[2]),
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

  const header = request.headers.get("cookie") || "";

  for (const part of header.split(";")) {
    const i = part.indexOf("=");

    if (i > 0) {
      const name = part
        .slice(0, i)
        .trim();

      const value = decodeURIComponent(
        part
          .slice(i + 1)
          .trim()
      );

      out[name] = value;
    }
  }

  return out;
}

// ============================================================
// HELPERS
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

function errorDetail(err) {
  return String(
    err?.message ||
    err ||
    "Unknown error"
  ).slice(0, 1000);
}

// ============================================================
// USER AUTH
// ============================================================

async function getUser(request, env) {
  const token =
    parseCookies(request).funlearn_session;

  if (!token) {
    return null;
  }

  const sid = await hashToken(token);

  const row = await env.DB.prepare(`
    SELECT
      u.id,
      u.username
    FROM sessions s
    JOIN users u
      ON u.id = s.user_id
    WHERE
      s.id_hash = ?
      AND s.expires_at > datetime('now')
  `)
    .bind(sid)
    .first();

  return row || null;
}

async function requireUser(request, env) {
  const user = await getUser(request, env);

  return user || null;
}

// ============================================================
// STATE
// ============================================================

async function readState(env, userId) {
  const row = await env.DB.prepare(`
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
      completedDate:
        p.completed
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
          video_url = excluded.video_url,
          current_time = excluded.current_time,
          duration = excluded.duration,
          progress_percentage = excluded.progress_percentage,
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
// GLOBAL COMMENTS SCHEMA
// ============================================================

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

// ============================================================
// GENERIC COLUMN CHECK
// ============================================================

async function ensureColumn(
  env,
  table,
  column,
  definition
) {
  const result =
    await env.DB
      .prepare(
        `PRAGMA table_info(${table})`
      )
      .all();

  const columns =
    result.results || [];

  if (
    !columns.some(
      c => c.name === column
    )
  ) {
    await env.DB.prepare(
      `ALTER TABLE ${table}
       ADD COLUMN ${column}
       ${definition}`
    ).run();
  }
}

// ============================================================
// PUBLIC VIDEO SCHEMA
//
// IMPORTANT:
// This function is compatible with your
// existing D1 tables.
//
// Existing public_videos:
//
// id
// owner_id
// title
// description
// object_key
// created_at
// user_id
// username
// module_title
// video_url
//
// Existing public_video_comments:
//
// id
// video_id
// user_id
// content
// created_at
// username
// comment
// updated_at
//
// We DO NOT drop/recreate existing tables.
// ============================================================

async function ensurePublicVideoSchema(env) {

  // ----------------------------------------------------------
  // PUBLIC VIDEOS
  // ----------------------------------------------------------

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS public_videos (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      object_key TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `).run();

  const videoColumns = [
    ["owner_id", "TEXT"],
    ["title", "TEXT"],
    ["description", "TEXT DEFAULT ''"],
    ["object_key", "TEXT"],
    ["created_at", "TEXT"],
    ["user_id", "TEXT"],
    ["username", "TEXT"],
    ["module_title", "TEXT"],
    ["video_url", "TEXT"]
  ];

  for (
    const [column, definition]
    of videoColumns
  ) {
    await ensureColumn(
      env,
      "public_videos",
      column,
      definition
    );
  }

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS
    idx_public_videos_created
    ON public_videos(created_at DESC)
  `).run();

  // ----------------------------------------------------------
  // PUBLIC VIDEO COMMENTS
  // ----------------------------------------------------------

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS public_video_comments (
      id TEXT PRIMARY KEY,
      video_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `).run();

  const commentColumns = [
    ["video_id", "TEXT"],
    ["user_id", "TEXT"],
    ["content", "TEXT"],
    ["created_at", "TEXT"],
    ["username", "TEXT"],
    ["comment", "TEXT"],
    ["updated_at", "TEXT"]
  ];

  for (
    const [column, definition]
    of commentColumns
  ) {
    await ensureColumn(
      env,
      "public_video_comments",
      column,
      definition
    );
  }

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS
    idx_public_video_comments_video
    ON public_video_comments(
      video_id,
      created_at
    )
  `).run();

  // ----------------------------------------------------------
  // PUBLIC VIDEO REPLIES
  // ----------------------------------------------------------

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

  const replyColumns = [
    ["comment_id", "TEXT"],
    ["video_id", "TEXT"],
    ["user_id", "TEXT"],
    ["username", "TEXT"],
    ["reply", "TEXT"],
    ["created_at", "TEXT"],
    ["updated_at", "TEXT"]
  ];

  for (
    const [column, definition]
    of replyColumns
  ) {
    await ensureColumn(
      env,
      "public_video_replies",
      column,
      definition
    );
  }

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS
    idx_public_video_replies_comment
    ON public_video_replies(
      comment_id,
      created_at
    )
  `).run();
}

// ============================================================
// MAIN REQUEST HANDLER
// ============================================================

export async function onRequest(context) {

  const {
    request,
    env,
    params
  } = context;

  if (!env.DB) {
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

    const route =
      "/" +
      (params.path || []).join("/");

    const method =
      request.method.toUpperCase();

    // --------------------------------------------------------
    // BODY
    //
    // Hanya request JSON yang diparse sebagai JSON.
    // GET/DELETE kosong tidak akan dianggap JSON.
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
          body =
            await request.json();
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
      }
    }

    // ========================================================
    // REGISTER
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
        String(
          body.password || ""
        );

      if (
        !USERNAME_RE.test(username) ||
        password.length <
          MIN_PASSWORD_LENGTH
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

      const userId =
        id("usr");

      const hash =
        await passwordHash(
          password
        );

      try {

        await env.DB.prepare(`
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

      } catch {

        return json(
          {
            error:
              "Username atau password tidak dapat digunakan."
          },
          400
        );
      }

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
          WHERE username = ?
          COLLATE NOCASE
        `)
          .bind(username)
          .first();

      if (
        !row ||
        !(
          await verifyPassword(
            password,
            row.password_hash
          )
        )
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

    // ========================================================
    // LOGOUT
    // ========================================================

    if (
      route === "/logout" &&
      method === "POST"
    ) {

      const token =
        parseCookies(
          request
        ).funlearn_session;

      if (token) {

        await env.DB.prepare(`
          DELETE FROM sessions
          WHERE id_hash = ?
        `)
          .bind(
            await hashToken(token)
          )
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

    const user =
      await requireUser(
        request,
        env
      );

    // ========================================================
    // PUBLIC VIDEO
    // GET LIST
    // ========================================================

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

            COALESCE(
              user_id,
              owner_id
            ) AS userId,

            COALESCE(
              username,
              ''
            ) AS username,

            title,

            COALESCE(
              module_title,
              ''
            ) AS moduleTitle,

            COALESCE(
              description,
              ''
            ) AS description,

            COALESCE(
              video_url,
              object_key
            ) AS videoUrl,

            created_at AS createdAt

          FROM public_videos

          ORDER BY created_at DESC

          LIMIT 500
        `)
          .all();

      return json(
        {
          ok: true,
          videos:
            result.results || []
        }
      );
    }

    // ========================================================
    // PUBLIC VIDEO
    // POST METADATA
    // ========================================================

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

      if (
        title.length > 160 ||
        moduleTitle.length > 100 ||
        description.length > 600 ||
        videoUrl.length > 2000
      ) {
        return json(
          {
            ok: false,
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
            ok: false,
            error:
              "URL video tidak valid."
          },
          400
        );
      }

      try {

        await ensurePublicVideoSchema(
          env
        );

        const videoId =
          id("pvideo");

        const ts =
          now();

        // ----------------------------------------------------
        // PENTING:
        //
        // owner_id WAJIB karena schema D1 kamu:
        // owner_id TEXT NOT NULL
        //
        // object_key WAJIB karena:
        // object_key TEXT NOT NULL
        //
        // Jadi keduanya harus diisi.
        // ----------------------------------------------------

        const result =
          await env.DB.prepare(`
            INSERT INTO public_videos(
              id,
              owner_id,
              title,
              description,
              object_key,
              created_at,
              user_id,
              username,
              module_title,
              video_url
            )
            VALUES(
              ?,
              ?,
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
              videoId,

              // owner_id
              String(user.id),

              // title
              title,

              // description
              description,

              // object_key
              videoUrl,

              // created_at
              ts,

              // user_id
              String(user.id),

              // username
              String(
                user.username
              ),

              // module_title
              moduleTitle,

              // video_url
              videoUrl
            )
            .run();

        if (
          result &&
          result.success === false
        ) {
          throw new Error(
            "D1 menolak INSERT public_videos."
          );
        }

        return json(
          {
            ok: true,

            video: {
              id: videoId,
              userId: user.id,
              username:
                user.username,
              title,
              moduleTitle,
              description,
              videoUrl,
              createdAt: ts
            }
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

    // ========================================================
    // DELETE PUBLIC VIDEO
    // ========================================================

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

      const video =
        await env.DB.prepare(`
          SELECT
            id,
            COALESCE(
              user_id,
              owner_id
            ) AS user_id
          FROM public_videos
          WHERE id = ?
        `)
          .bind(videoId)
          .first();

      if (!video) {
        return json(
          {
            error:
              "Video tidak ditemukan."
          },
          404
        );
      }

      const allowed =
        String(
          video.user_id
        ) ===
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
          WHERE video_id = ?
        `)
          .bind(videoId),

        env.DB.prepare(`
          DELETE FROM public_video_comments
          WHERE video_id = ?
        `)
          .bind(videoId),

        env.DB.prepare(`
          DELETE FROM public_videos
          WHERE id = ?
        `)
          .bind(videoId)
      ]);

      return json(
        {
          ok: true,
          deleted: true,
          videoId
        }
      );
    }

    // ========================================================
    // PUBLIC VIDEO COMMENTS
    // GET COMMENTS
    // ========================================================

    const publicVideoCommentsMatch =
      route.match(
        /^\/public-videos\/([^/]+)\/comments$/
      );

    if (
      publicVideoCommentsMatch &&
      method === "GET"
    ) {

      await ensurePublicVideoSchema(
        env
      );

      const videoId =
        publicVideoCommentsMatch[1];

      const video =
        await env.DB.prepare(`
          SELECT id
          FROM public_videos
          WHERE id = ?
        `)
          .bind(videoId)
          .first();

      if (!video) {
        return json(
          {
            error:
              "Video tidak ditemukan."
          },
          404
        );
      }

      const commentsResult =
        await env.DB.prepare(`
          SELECT
            id,
            user_id AS userId,
            username,

            COALESCE(
              comment,
              content
            ) AS comment,

            created_at AS createdAt,
            updated_at AS updatedAt

          FROM public_video_comments

          WHERE video_id = ?

          ORDER BY created_at ASC
        `)
          .bind(videoId)
          .all();

      const repliesResult =
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

          WHERE video_id = ?

          ORDER BY created_at ASC
        `)
          .bind(videoId)
          .all();

      const replies =
        repliesResult.results || [];

      const comments =
        (
          commentsResult.results || []
        ).map(comment => ({
          ...comment,

          replies:
            replies.filter(
              reply =>
                String(
                  reply.commentId
                ) ===
                String(
                  comment.id
                )
            )
        }));

      return json(
        {
          ok: true,
          comments
        }
      );
    }

    // ========================================================
    // POST PUBLIC VIDEO COMMENT
    // ========================================================

    if (
      publicVideoCommentsMatch &&
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
        publicVideoCommentsMatch[1];

      const video =
        await env.DB.prepare(`
          SELECT id
          FROM public_videos
          WHERE id = ?
        `)
          .bind(videoId)
          .first();

      if (!video) {
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

      // ------------------------------------------------------
      // content WAJIB pada schema D1 kamu.
      // comment juga diisi agar kompatibel dengan kode lama.
      // ------------------------------------------------------

      await env.DB.prepare(`
        INSERT INTO public_video_comments(
          id,
          video_id,
          user_id,
          content,
          created_at,
          username,
          comment,
          updated_at
        )
        VALUES(
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
          commentId,
          videoId,
          user.id,
          comment,
          ts,
          user.username,
          comment,
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
            username:
              user.username,
            comment,
            createdAt: ts,
            updatedAt: ts,
            replies: []
          }
        },
        201
      );
    }

    // ========================================================
    // PUBLIC VIDEO REPLY
    // ========================================================

    const publicVideoReplyMatch =
      route.match(
        /^\/public-videos\/([^/]+)\/comments\/([^/]+)\/replies$/
      );

    if (
      publicVideoReplyMatch &&
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
        publicVideoReplyMatch[1];

      const commentId =
        publicVideoReplyMatch[2];

      const parent =
        await env.DB.prepare(`
          SELECT id
          FROM public_video_comments
          WHERE
            id = ?
            AND video_id = ?
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
          body.reply ||
          body.comment ||
          body.text ||
          ""
        ).trim();

      if (!reply) {
        return json(
          {
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
            error:
              "Reply maksimal 2000 karakter."
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
        VALUES(
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
            username:
              user.username,
            reply,
            createdAt: ts,
            updatedAt: ts
          }
        },
        201
      );
    }

    // ========================================================
    // DELETE PUBLIC VIDEO COMMENT
    // ========================================================

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
        publicVideoCommentDeleteMatch[1];

      const commentId =
        publicVideoCommentDeleteMatch[2];

      const comment =
        await env.DB.prepare(`
          SELECT
            id,
            user_id
          FROM public_video_comments
          WHERE
            id = ?
            AND video_id = ?
        `)
          .bind(
            commentId,
            videoId
          )
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

      const allowed =
        String(
          comment.user_id
        ) ===
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
          WHERE comment_id = ?
        `)
          .bind(commentId),

        env.DB.prepare(`
          DELETE FROM public_video_comments
          WHERE id = ?
        `)
          .bind(commentId)
      ]);

      return json(
        {
          ok: true,
          deleted: true,
          commentId
        }
      );
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
        publicVideoReplyDeleteMatch[1];

      const replyId =
        publicVideoReplyDeleteMatch[2];

      const reply =
        await env.DB.prepare(`
          SELECT
            id,
            user_id
          FROM public_video_replies
          WHERE
            id = ?
            AND video_id = ?
        `)
          .bind(
            replyId,
            videoId
          )
          .first();

      if (!reply) {
        return json(
          {
            error:
              "Reply tidak ditemukan."
          },
          404
        );
      }

      const allowed =
        String(
          reply.user_id
        ) ===
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
        WHERE id = ?
      `)
        .bind(replyId)
        .run();

      return json(
        {
          ok: true,
          deleted: true,
          replyId
        }
      );
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
          WHERE user_id = ?
        `)
          .bind(user.id),

        env.DB.prepare(`
          DELETE FROM user_data
          WHERE user_id = ?
        `)
          .bind(user.id),

        env.DB.prepare(`
          DELETE FROM public_video_replies
          WHERE user_id = ?
        `)
          .bind(user.id),

        env.DB.prepare(`
          DELETE FROM public_video_comments
          WHERE user_id = ?
        `)
          .bind(user.id),

        env.DB.prepare(`
          DELETE FROM public_video_replies
          WHERE video_id IN (
            SELECT id
            FROM public_videos
            WHERE COALESCE(
              user_id,
              owner_id
            ) = ?
          )
        `)
          .bind(user.id),

        env.DB.prepare(`
          DELETE FROM public_video_comments
          WHERE video_id IN (
            SELECT id
            FROM public_videos
            WHERE COALESCE(
              user_id,
              owner_id
            ) = ?
          )
        `)
          .bind(user.id),

        env.DB.prepare(`
          DELETE FROM public_videos
          WHERE COALESCE(
            user_id,
            owner_id
          ) = ?
        `)
          .bind(user.id),

        env.DB.prepare(`
          DELETE FROM sessions
          WHERE user_id = ?
        `)
          .bind(user.id),

        env.DB.prepare(`
          DELETE FROM users
          WHERE id = ?
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

    // ========================================================
    // GLOBAL COMMENTS API
    // ========================================================

    // --------------------------------------------------------
    // GET /api/comments
    // --------------------------------------------------------

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
        `)
          .all();

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
        `)
          .all();

      const replyMap =
        new Map();

      for (
        const r
        of repliesResult.results || []
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
            replyMap.get(
              c.id
            ) || []
        }));

      return json(
        {
          ok: true,
          comments
        }
      );
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
        VALUES(
          ?,
          ?,
          ?,
          ?,
          ?,
          ?
        )
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
            username:
              user.username,
            comment,
            createdAt:
              timestamp,
            updatedAt:
              timestamp
          }
        },
        201
      );
    }

    // --------------------------------------------------------
    // POST /api/comments/:id/replies
    // --------------------------------------------------------

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
          WHERE id = ?
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
        VALUES(
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
            username:
              user.username,
            reply,
            createdAt:
              timestamp,
            updatedAt:
              timestamp
          }
        },
        201
      );
    }

    // --------------------------------------------------------
    // DELETE /api/comments/reply/:id
    // --------------------------------------------------------

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
          WHERE id = ?
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
        String(
          row.user_id
        ) ===
        String(user.id);

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
        WHERE id = ?
      `)
        .bind(replyId)
        .run();

      return json(
        {
          ok: true,
          deleted: true,
          replyId
        }
      );
    }

    // --------------------------------------------------------
    // DELETE /api/comments/:id
    // --------------------------------------------------------

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
        String(
          comment.user_id
        ) ===
        String(user.id);

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
        WHERE id = ?
      `)
        .bind(commentId)
        .run();

      return json(
        {
          ok: true,
          deleted: true,
          commentId
        }
      );
    }

    // ========================================================
    // /ME
    // ========================================================

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

      return json(
        {
          user,
          state:
            await readState(
              env,
              user.id
            )
        }
      );
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

      return json(
        {
          ok: true,
          syncedAt: now()
        }
      );
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

            [
              String(
                body.moduleId
              )
            ]: body
          }
        }
      );

      return json(
        {
          ok: true
        }
      );
    }

    // ========================================================
    // NOT FOUND
    // ========================================================

    return json(
      {
        ok: false,
        error:
          "Not found"
      },
      404
    );

  } catch (err) {

    console.error(
      "FUNLEARN_API_ERROR",
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

// ============================================================
// CREATE SESSION
// ============================================================

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
    VALUES(
      ?,
      ?,
      ?,
      ?
    )
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
