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
    const raw = String(stored).split("$");

    if (
      raw.length !== 4 ||
      raw[0] !== "pbkdf2_sha256"
    ) {
      return false;
    }

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
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookie(name) {
  return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function parseCookies(request) {
  const out = {};

  for (
    const part of (
      request.headers.get("cookie") || ""
    ).split(";")
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

function errorDetail(err) {
  return String(
    err?.message || err || "Unknown error"
  ).slice(0, 1000);
}

async function getUser(request, env) {
  const token =
    parseCookies(request).funlearn_session;

  if (!token) return null;

  const sid = await hashToken(token);

  return await env.DB
    .prepare(
      "SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=? AND s.expires_at>datetime('now')"
    )
    .bind(sid)
    .first();
}

async function readState(env, userId) {
  const row = await env.DB
    .prepare(
      "SELECT schema_version,app_database_json,online_data_json,rewards_json FROM user_data WHERE user_id=?"
    )
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
    .prepare(
      "SELECT module_id,video_url,current_time,duration,progress_percentage,completed,last_watched_at FROM video_progress WHERE user_id=?"
    )
    .bind(userId)
    .all();

  for (const p of progress.results || []) {
    state.onlineProgress[p.module_id] = {
      currentTime: p.current_time,
      duration: p.duration,
      percent: p.progress_percentage,
      completed: !!p.completed,
      completedDate: p.completed
        ? (p.last_watched_at || "").slice(
            0,
            10
          )
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
    .prepare(
      "INSERT INTO user_data(user_id,schema_version,app_database_json,online_data_json,rewards_json,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET schema_version=excluded.schema_version,app_database_json=excluded.app_database_json,online_data_json=excluded.online_data_json,rewards_json=excluded.rewards_json,updated_at=excluded.updated_at"
    )
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
    const [moduleId, p] of Object.entries(
      modules
    ).slice(0, 5000)
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
      Math.max(
        0,
        Number(p.percent) || 0
      )
    );

    const completed =
      p.completed === true ? 1 : 0;

    stmts.push(
      env.DB
        .prepare(
          "INSERT INTO video_progress(user_id,module_id,video_url,current_time,duration,progress_percentage,completed,last_watched_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(user_id,module_id) DO UPDATE SET video_url=excluded.video_url,current_time=excluded.current_time,duration=excluded.duration,progress_percentage=excluded.progress_percentage,completed=MAX(video_progress.completed,excluded.completed),last_watched_at=excluded.last_watched_at"
        )
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

async function ensureColumn(
  env,
  table,
  column,
  definition
) {
  const result = await env.DB
    .prepare(
      `PRAGMA table_info(${table})`
    )
    .all();

  if (
    !(result.results || []).some(
      c => c.name === column
    )
  ) {
    await env.DB
      .prepare(
        `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
      )
      .run();
  }
}

async function ensureReplySchema(env) {
  await env.DB
    .prepare(
      `CREATE TABLE IF NOT EXISTS comment_replies (
        id TEXT PRIMARY KEY,
        comment_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        username TEXT NOT NULL,
        reply TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`
    )
    .run();

  await env.DB
    .prepare(
      `CREATE INDEX IF NOT EXISTS idx_comment_replies_comment
       ON comment_replies(comment_id,created_at)`
    )
    .run();
}

async function ensureGlobalCommentSchema(env) {
  await env.DB
    .prepare(
      `CREATE TABLE IF NOT EXISTS comments (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        username TEXT NOT NULL,
        comment TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`
    )
    .run();

  for (
    const [c, d] of [
      ["user_id", "TEXT"],
      ["username", "TEXT"],
      ["comment", "TEXT"],
      ["created_at", "TEXT"],
      ["updated_at", "TEXT"]
    ]
  ) {
    await ensureColumn(
      env,
      "comments",
      c,
      d
    );
  }

  await ensureReplySchema(env);

  await env.DB
    .prepare(
      `CREATE TABLE IF NOT EXISTS comment_likes (
        comment_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(comment_id,user_id)
      )`
    )
    .run();

  await env.DB
    .prepare(
      `CREATE TABLE IF NOT EXISTS comment_reply_likes (
        reply_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(reply_id,user_id)
      )`
    )
    .run();
}

async function ensurePublicVideoSchema(env) {
  await env.DB
    .prepare(
      `CREATE TABLE IF NOT EXISTS public_videos (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        username TEXT,
        title TEXT NOT NULL,
        module_title TEXT NOT NULL,
        description TEXT,
        video_url TEXT NOT NULL,
        created_at TEXT NOT NULL,
        owner_id TEXT,
        object_key TEXT,
        category TEXT,
        thumbnail_url TEXT,
        views INTEGER NOT NULL DEFAULT 0
      )`
    )
    .run();

  for (
    const [c, d] of [
      ["user_id", "TEXT"],
      ["username", "TEXT"],
      ["title", "TEXT"],
      ["module_title", "TEXT"],
      ["description", "TEXT"],
      ["video_url", "TEXT"],
      ["created_at", "TEXT"],
      ["owner_id", "TEXT"],
      ["object_key", "TEXT"],
      ["category", "TEXT"],
      ["thumbnail_url", "TEXT"],
      ["views", "INTEGER NOT NULL DEFAULT 0"]
    ]
  ) {
    await ensureColumn(
      env,
      "public_videos",
      c,
      d
    );
  }

  await env.DB
    .prepare(
      `CREATE INDEX IF NOT EXISTS idx_public_videos_created
       ON public_videos(created_at DESC)`
    )
    .run();

  await env.DB
    .prepare(
      `CREATE TABLE IF NOT EXISTS public_video_reactions (
        video_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        reaction TEXT NOT NULL
          CHECK(reaction IN ('like','dislike')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY(video_id,user_id)
      )`
    )
    .run();

  await env.DB
    .prepare(
      `CREATE TABLE IF NOT EXISTS public_video_views (
        video_id TEXT NOT NULL,
        viewer_key TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        PRIMARY KEY(video_id,viewer_key)
      )`
    )
    .run();

  await env.DB
    .prepare(
      `CREATE TABLE IF NOT EXISTS public_video_comment_likes (
        comment_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(comment_id,user_id)
      )`
    )
    .run();

  await env.DB
    .prepare(
      `CREATE TABLE IF NOT EXISTS public_video_notes (
        video_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL,
        PRIMARY KEY(video_id,user_id)
      )`
    )
    .run();

  await env.DB
    .prepare(
      `CREATE TABLE IF NOT EXISTS public_video_replies (
        id TEXT PRIMARY KEY,
        comment_id TEXT NOT NULL,
        video_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        username TEXT NOT NULL,
        reply TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`
    )
    .run();

  for (
    const [c, d] of [
      ["comment_id", "TEXT"],
      ["video_id", "TEXT"],
      ["user_id", "TEXT"],
      ["username", "TEXT"],
      ["reply", "TEXT"],
      ["created_at", "TEXT"],
      ["updated_at", "TEXT"]
    ]
  ) {
    await ensureColumn(
      env,
      "public_video_replies",
      c,
      d
    );
  }

  await env.DB
    .prepare(
      `CREATE INDEX IF NOT EXISTS idx_public_video_replies_comment
       ON public_video_replies(comment_id,created_at)`
    )
    .run();

  await env.DB
    .prepare(
      `CREATE TABLE IF NOT EXISTS public_video_comments (
        id TEXT PRIMARY KEY,
        video_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        username TEXT NOT NULL,
        content TEXT NOT NULL,
        comment TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`
    )
    .run();

  for (
    const [c, d] of [
      ["video_id", "TEXT"],
      ["user_id", "TEXT"],
      ["username", "TEXT"],
      ["content", "TEXT"],
      ["comment", "TEXT"],
      ["created_at", "TEXT"],
      ["updated_at", "TEXT"]
    ]
  ) {
    await ensureColumn(
      env,
      "public_video_comments",
      c,
      d
    );
  }

  await env.DB
    .prepare(
      `CREATE INDEX IF NOT EXISTS idx_public_video_comments_video
       ON public_video_comments(video_id,created_at)`
    )
    .run();
}

async function publicVideoRow(
  env,
  idValue,
  userId = null
) {
  return await env.DB
    .prepare(
      `SELECT
        v.id,
        COALESCE(v.user_id,v.owner_id) AS userId,
        COALESCE(v.username,'') AS username,
        v.title,
        COALESCE(v.module_title,'') AS moduleTitle,
        COALESCE(v.description,'') AS description,
        COALESCE(v.video_url,v.object_key) AS videoUrl,
        COALESCE(v.category,'Lainnya') AS category,
        COALESCE(v.thumbnail_url,'') AS thumbnailUrl,
        v.created_at AS createdAt,
        COALESCE(v.views,0) AS views,

        (
          SELECT COUNT(*)
          FROM public_video_reactions r
          WHERE r.video_id=v.id
          AND r.reaction='like'
        ) AS likes,

        (
          SELECT COUNT(*)
          FROM public_video_reactions r
          WHERE r.video_id=v.id
          AND r.reaction='dislike'
        ) AS dislikes,

        ${
          userId
            ? "(SELECT reaction FROM public_video_reactions r WHERE r.video_id=v.id AND r.user_id=? LIMIT 1)"
            : "NULL"
        } AS viewerReaction

      FROM public_videos v
      WHERE v.id=?`
    )
    .bind(
      ...(userId
        ? [userId, idValue]
        : [idValue])
    )
    .first();
}

export async function onRequest(
  context
) {
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

    let body = {};

    if (
      method !== "GET" &&
      method !== "HEAD" &&
      method !== "DELETE" &&
      method !== "OPTIONS"
    ) {
      const ct =
        request.headers.get(
          "content-type"
        ) || "";

      if (
        ct.includes(
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
      }
    }

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
        !USERNAME_RE.test(
          username
        ) ||
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

      const userId = id("usr");
      const ts = now();
      const hash =
        await passwordHash(password);

      try {
        await env.DB
          .prepare(
            "INSERT INTO users(id,username,password_hash,created_at,updated_at) VALUES(?,?,?,?,?)"
          )
          .bind(
            userId,
            username,
            hash,
            ts,
            ts
          )
          .run();
      } catch (e) {
        return json(
          {
            error:
              "Username sudah digunakan atau gagal membuat akun."
          },
          409
        );
      }

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
        String(body.password || "");

      const u = await env.DB
        .prepare(
          "SELECT id,username,password_hash FROM users WHERE username=? COLLATE NOCASE"
        )
        .bind(username)
        .first();

      if (
        !u ||
        !(await verifyPassword(
          password,
          u.password_hash
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
        u.id,
        u.username
      );
    }

    if (
      route === "/logout" &&
      method === "POST"
    ) {
      const token =
        parseCookies(request)
          .funlearn_session;

      if (token) {
        await env.DB
          .prepare(
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
      await getUser(
        request,
        env
      );

    // ============================================================
    // PUBLIC VIDEO
    // ============================================================

    if (
      route === "/public-videos" &&
      method === "GET"
    ) {
      await ensurePublicVideoSchema(
        env
      );

      const result =
        await env.DB
          .prepare(
            `SELECT
              v.id,
              COALESCE(v.user_id,v.owner_id) AS userId,
              COALESCE(v.username,'') AS username,
              v.title,
              COALESCE(v.module_title,'') AS moduleTitle,
              COALESCE(v.description,'') AS description,
              COALESCE(v.video_url,v.object_key) AS videoUrl,
              COALESCE(v.category,'Lainnya') AS category,
              COALESCE(v.thumbnail_url,'') AS thumbnailUrl,
              v.created_at AS createdAt,
              COALESCE(v.views,0) AS views,

              (
                SELECT COUNT(*)
                FROM public_video_reactions r
                WHERE r.video_id=v.id
                AND r.reaction='like'
              ) AS likes,

              (
                SELECT COUNT(*)
                FROM public_video_reactions r
                WHERE r.video_id=v.id
                AND r.reaction='dislike'
              ) AS dislikes,

              ${
                user
                  ? "(SELECT reaction FROM public_video_reactions r WHERE r.video_id=v.id AND r.user_id=? LIMIT 1)"
                  : "NULL"
              } AS viewerReaction

            FROM public_videos v
            ORDER BY v.created_at DESC
            LIMIT 500`
          )
          .bind(
            ...(user
              ? [user.id]
              : [])
          )
          .all();

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

      const category =
        String(
          body.category || ""
        ).trim();

      const description =
        String(
          body.description || ""
        ).trim();

      const videoUrl =
        String(
          body.videoUrl || ""
        ).trim();

      /*
       * Thumbnail sekarang boleh berupa:
       * - data:image/jpeg;base64,...
       * - URL HTTPS biasa
       *
       * Jadi thumbnail TIDAK perlu dikirim ke Top4Top.
       */
      const thumbnailUrl =
        String(
          body.thumbnailUrl || ""
        ).trim();

      if (
        !title ||
        !moduleTitle ||
        !category ||
        !videoUrl
      ) {
        return json(
          {
            error:
              "Judul video, judul modul, kategori, dan URL video wajib diisi."
          },
          400
        );
      }

      if (
        title.length > 160 ||
        moduleTitle.length > 100 ||
        category.length > 80 ||
        description.length > 600 ||
        videoUrl.length > 4000 ||
        thumbnailUrl.length > 350000
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

      if (
        thumbnailUrl &&
        !/^https:\/\//i.test(
          thumbnailUrl
        ) &&
        !/^data:image\/(jpeg|jpg|png|webp);base64,/i.test(
          thumbnailUrl
        )
      ) {
        return json(
          {
            error:
              "Format thumbnail tidak valid."
          },
          400
        );
      }

      const videoId =
        id("pvideo");

      const ts = now();

      await env.DB
        .prepare(
          `INSERT INTO public_videos(
            id,
            owner_id,
            title,
            description,
            object_key,
            created_at,
            user_id,
            username,
            module_title,
            video_url,
            category,
            thumbnail_url,
            views
          )
          VALUES(
            ?,?,?,?,?,?,?,?,?,?,?,?,0
          )`
        )
        .bind(
          videoId,
          user.id,
          title,
          description,
          videoUrl,
          ts,
          user.id,
          user.username,
          moduleTitle,
          videoUrl,
          category,
          thumbnailUrl
        )
        .run();

      return json(
        {
          ok: true,
          video:
            await publicVideoRow(
              env,
              videoId,
              user.id
            )
        },
        201
      );
    }

    const pvm =
      route.match(
        /^\/public-videos\/([^/]+)$/
      );

    if (
      pvm &&
      method === "PATCH"
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

      const vid = pvm[1];

      const old =
        await env.DB
          .prepare(
            "SELECT id,COALESCE(user_id,owner_id) AS owner_id,title,module_title,description,category,thumbnail_url FROM public_videos WHERE id=?"
          )
          .bind(vid)
          .first();

      if (!old) {
        return json(
          {
            error:
              "Video tidak ditemukan."
          },
          404
        );
      }

      if (
        String(old.owner_id) !==
          String(user.id) &&
        String(
          user.username
        ).toLowerCase() !==
          "fazmen"
      ) {
        return json(
          {
            error:
              "Hanya pemilik video yang dapat mengedit."
          },
          403
        );
      }

      const title =
        String(
          body.title ??
            old.title
        ).trim();

      const moduleTitle =
        String(
          body.moduleTitle ??
            old.module_title
        ).trim();

      const category =
        String(
          body.category ??
            old.category ??
            "Lainnya"
        ).trim();

      const description =
        String(
          body.description ??
            old.description ??
            ""
        ).trim();

      const thumbnailUrl =
        String(
          body.thumbnailUrl ??
            old.thumbnail_url ??
            ""
        ).trim();

      if (
        !title ||
        !moduleTitle ||
        !category
      ) {
        return json(
          {
            error:
              "Judul, modul, dan kategori wajib diisi."
          },
          400
        );
      }

      if (
        title.length > 160 ||
        moduleTitle.length > 100 ||
        category.length > 80 ||
        description.length > 600 ||
        thumbnailUrl.length > 350000
      ) {
        return json(
          {
            error:
              "Data melebihi batas panjang."
          },
          400
        );
      }

      if (
        thumbnailUrl &&
        !/^https:\/\//i.test(
          thumbnailUrl
        ) &&
        !/^data:image\/(jpeg|jpg|png|webp);base64,/i.test(
          thumbnailUrl
        )
      ) {
        return json(
          {
            error:
              "Format thumbnail tidak valid."
          },
          400
        );
      }

      await env.DB
        .prepare(
          "UPDATE public_videos SET title=?,module_title=?,category=?,description=?,thumbnail_url=? WHERE id=?"
        )
        .bind(
          title,
          moduleTitle,
          category,
          description,
          thumbnailUrl,
          vid
        )
        .run();

      return json({
        ok: true,
        video:
          await publicVideoRow(
            env,
            vid,
            user.id
          )
      });
    }

    if (
      pvm &&
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

      const vid = pvm[1];

      const v =
        await env.DB
          .prepare(
            "SELECT id,COALESCE(user_id,owner_id) AS owner_id FROM public_videos WHERE id=?"
          )
          .bind(vid)
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

      if (
        String(v.owner_id) !==
          String(user.id) &&
        String(
          user.username
        ).toLowerCase() !==
          "fazmen"
      ) {
        return json(
          {
            error:
              "Kamu tidak memiliki izin untuk menghapus video ini."
          },
          403
        );
      }

      await env.DB.batch([
        env.DB
          .prepare(
            "DELETE FROM public_video_replies WHERE video_id=?"
          )
          .bind(vid),

        env.DB
          .prepare(
            "DELETE FROM public_video_comments WHERE video_id=?"
          )
          .bind(vid),

        env.DB
          .prepare(
            "DELETE FROM public_video_reactions WHERE video_id=?"
          )
          .bind(vid),

        env.DB
          .prepare(
            "DELETE FROM public_video_views WHERE video_id=?"
          )
          .bind(vid),

        env.DB
          .prepare(
            "DELETE FROM public_video_notes WHERE video_id=?"
          )
          .bind(vid),

        env.DB
          .prepare(
            "DELETE FROM public_videos WHERE id=?"
          )
          .bind(vid)
      ]);

      return json({
        ok: true,
        deleted: true,
        videoId: vid
      });
    }

    const pview =
      route.match(
        /^\/public-videos\/([^/]+)\/view$/
      );

    if (
      pview &&
      method === "POST"
    ) {
      await ensurePublicVideoSchema(
        env
      );

      const vid = pview[1];

      const v =
        await env.DB
          .prepare(
            "SELECT id FROM public_videos WHERE id=?"
          )
          .bind(vid)
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

      const cookies =
        parseCookies(request);

      let device =
        cookies.funlearn_view_device;

      let setCookie = null;

      if (!device) {
        device =
          b64(randomBytes(24));

        setCookie = cookie(
          "funlearn_view_device",
          device,
          31536000
        );
      }

      const viewerKey =
        await hashToken(device);

      const existing =
        await env.DB
          .prepare(
            "SELECT video_id FROM public_video_views WHERE video_id=? AND viewer_key=?"
          )
          .bind(
            vid,
            viewerKey
          )
          .first();

      if (!existing) {
        await env.DB.batch([
          env.DB
            .prepare(
              "INSERT INTO public_video_views(video_id,viewer_key,created_at,last_seen_at) VALUES(?,?,?,?)"
            )
            .bind(
              vid,
              viewerKey,
              now(),
              now()
            ),

          env.DB
            .prepare(
              "UPDATE public_videos SET views=COALESCE(views,0)+1 WHERE id=?"
            )
            .bind(vid)
        ]);
      } else {
        await env.DB
          .prepare(
            "UPDATE public_video_views SET last_seen_at=? WHERE video_id=? AND viewer_key=?"
          )
          .bind(
            now(),
            vid,
            viewerKey
          )
          .run();
      }

      const row =
        await publicVideoRow(
          env,
          vid,
          user?.id || null
        );

      return json(
        {
          ok: true,
          counted: !existing,
          video: row
        },
        200,
        setCookie
          ? {
              "set-cookie":
                setCookie
            }
          : {}
      );
    }

    const pvreact =
      route.match(
        /^\/public-videos\/([^/]+)\/reaction$/
      );

    if (
      pvreact &&
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

      const vid =
        pvreact[1];

      const reaction =
        String(
          body.type || ""
        ).toLowerCase();

      if (
        !["like", "dislike"].includes(
          reaction
        )
      ) {
        return json(
          {
            error:
              "Reaction tidak valid."
          },
          400
        );
      }

      const v =
        await env.DB
          .prepare(
            "SELECT id FROM public_videos WHERE id=?"
          )
          .bind(vid)
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

      const old =
        await env.DB
          .prepare(
            "SELECT reaction FROM public_video_reactions WHERE video_id=? AND user_id=?"
          )
          .bind(
            vid,
            user.id
          )
          .first();

      if (
        old?.reaction ===
        reaction
      ) {
        await env.DB
          .prepare(
            "DELETE FROM public_video_reactions WHERE video_id=? AND user_id=?"
          )
          .bind(
            vid,
            user.id
          )
          .run();
      } else {
        await env.DB
          .prepare(
            "INSERT INTO public_video_reactions(video_id,user_id,reaction,created_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(video_id,user_id) DO UPDATE SET reaction=excluded.reaction,updated_at=excluded.updated_at"
          )
          .bind(
            vid,
            user.id,
            reaction,
            now(),
            now()
          )
          .run();
      }

      return json({
        ok: true,
        video:
          await publicVideoRow(
            env,
            vid,
            user.id
          )
      });
    }

    const pvnote =
      route.match(
        /^\/public-videos\/([^/]+)\/note$/
      );

    if (
      pvnote &&
      method === "GET"
    ) {
      if (!user) {
        return json(
          {
            error:
              "Kamu harus login untuk memakai notes."
          },
          401
        );
      }

      await ensurePublicVideoSchema(
        env
      );

      const r =
        await env.DB
          .prepare(
            "SELECT note,updated_at AS updatedAt FROM public_video_notes WHERE video_id=? AND user_id=?"
          )
          .bind(
            pvnote[1],
            user.id
          )
          .first();

      return json({
        ok: true,
        note: r?.note || "",
        updatedAt:
          r?.updatedAt || null
      });
    }

    if (
      pvnote &&
      method === "PUT"
    ) {
      if (!user) {
        return json(
          {
            error:
              "Kamu harus login untuk memakai notes."
          },
          401
        );
      }

      await ensurePublicVideoSchema(
        env
      );

      const note =
        String(
          body.note || ""
        );

      if (note.length > 5000) {
        return json(
          {
            error:
              "Notes maksimal 5000 karakter."
          },
          400
        );
      }

      const ts = now();

      await env.DB
        .prepare(
          "INSERT INTO public_video_notes(video_id,user_id,note,updated_at) VALUES(?,?,?,?) ON CONFLICT(video_id,user_id) DO UPDATE SET note=excluded.note,updated_at=excluded.updated_at"
        )
        .bind(
          pvnote[1],
          user.id,
          note,
          ts
        )
        .run();

      return json({
        ok: true,
        note,
        updatedAt: ts
      });
    }

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

      const vid = pvc[1];

      const cr =
        await env.DB
          .prepare(
            `SELECT
              c.id,
              c.video_id AS videoId,
              c.user_id AS userId,
              c.username,
              c.comment,
              c.created_at AS createdAt,
              c.updated_at AS updatedAt,

              (
                SELECT COUNT(*)
                FROM public_video_comment_likes l
                WHERE l.comment_id=c.id
              ) AS likes,

              ${
                user
                  ? "EXISTS(SELECT 1 FROM public_video_comment_likes l WHERE l.comment_id=c.id AND l.user_id=?)"
                  : "0"
              } AS liked

            FROM public_video_comments c
            WHERE c.video_id=?
            ORDER BY c.created_at ASC`
          )
          .bind(
            ...(user
              ? [
                  user.id,
                  vid
                ]
              : [vid])
          )
          .all();

      const rr =
        await env.DB
          .prepare(
            "SELECT id,comment_id AS commentId,video_id AS videoId,user_id AS userId,username,reply,created_at AS createdAt,updated_at AS updatedAt FROM public_video_replies WHERE video_id=? ORDER BY created_at ASC"
          )
          .bind(vid)
          .all();

      const comments =
        (cr.results || []).map(
          c => ({
            ...c,
            liked: !!c.liked,
            replies:
              (rr.results || [])
                .filter(
                  r =>
                    String(
                      r.commentId
                    ) ===
                    String(c.id)
                )
          })
        );

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

      const vid = pvc[1];

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

      if (comment.length > 2000) {
        return json(
          {
            error:
              "Komentar maksimal 2000 karakter."
          },
          400
        );
      }

      const cid =
        id("pvcomment");

      const ts = now();

      await env.DB
        .prepare(
          "INSERT INTO public_video_comments(id,video_id,user_id,username,content,comment,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)"
        )
        .bind(
          cid,
          vid,
          user.id,
          user.username,
          comment,
          comment,
          ts,
          ts
        )
        .run();

      return json(
        {
          ok: true,
          comment: {
            id: cid,
            videoId: vid,
            userId: user.id,
            username:
              user.username,
            comment,
            createdAt: ts,
            updatedAt: ts,
            likes: 0,
            liked: false,
            replies: []
          }
        },
        201
      );
    }

    const pvcl =
      route.match(
        /^\/public-videos\/([^/]+)\/comments\/([^/]+)\/like$/
      );

    if (
      pvcl &&
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

      const vid = pvcl[1];
      const cid = pvcl[2];

      const c =
        await env.DB
          .prepare(
            "SELECT id FROM public_video_comments WHERE id=? AND video_id=?"
          )
          .bind(cid, vid)
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

      const old =
        await env.DB
          .prepare(
            "SELECT comment_id FROM public_video_comment_likes WHERE comment_id=? AND user_id=?"
          )
          .bind(
            cid,
            user.id
          )
          .first();

      if (old) {
        await env.DB
          .prepare(
            "DELETE FROM public_video_comment_likes WHERE comment_id=? AND user_id=?"
          )
          .bind(
            cid,
            user.id
          )
          .run();
      } else {
        await env.DB
          .prepare(
            "INSERT INTO public_video_comment_likes(comment_id,user_id,created_at) VALUES(?,?,?)"
          )
          .bind(
            cid,
            user.id,
            now()
          )
          .run();
      }

      const count =
        await env.DB
          .prepare(
            "SELECT COUNT(*) AS n FROM public_video_comment_likes WHERE comment_id=?"
          )
          .bind(cid)
          .first();

      return json({
        ok: true,
        liked: !old,
        likes:
          Number(count?.n) || 0
      });
    }

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

      const vid = pvr[1];
      const cid = pvr[2];

      const parent =
        await env.DB
          .prepare(
            "SELECT id FROM public_video_comments WHERE id=? AND video_id=?"
          )
          .bind(cid, vid)
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
              "Balasan tidak boleh kosong."
          },
          400
        );
      }

      if (reply.length > 2000) {
        return json(
          {
            error:
              "Balasan maksimal 2000 karakter."
          },
          400
        );
      }

      const rid =
        id("pvreply");

      const ts = now();

      await env.DB
        .prepare(
          "INSERT INTO public_video_replies(id,comment_id,video_id,user_id,username,reply,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)"
        )
        .bind(
          rid,
          cid,
          vid,
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
            id: rid,
            commentId: cid,
            videoId: vid,
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

      const vid = pvcd[1];
      const cid = pvcd[2];

      const c =
        await env.DB
          .prepare(
            "SELECT id,user_id FROM public_video_comments WHERE id=? AND video_id=?"
          )
          .bind(cid, vid)
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

      if (
        String(c.user_id) !==
          String(user.id) &&
        String(
          user.username
        ).toLowerCase() !==
          "fazmen"
      ) {
        return json(
          {
            error:
              "Kamu tidak memiliki izin untuk menghapus komentar ini."
          },
          403
        );
      }

      await env.DB.batch([
        env.DB
          .prepare(
            "DELETE FROM public_video_comment_likes WHERE comment_id=?"
          )
          .bind(cid),

        env.DB
          .prepare(
            "DELETE FROM public_video_replies WHERE comment_id=?"
          )
          .bind(cid),

        env.DB
          .prepare(
            "DELETE FROM public_video_comments WHERE id=?"
          )
          .bind(cid)
      ]);

      return json({
        ok: true,
        deleted: true,
        commentId: cid
      });
    }

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

      const rid = pvrd[2];

      const r =
        await env.DB
          .prepare(
            "SELECT id,user_id FROM public_video_replies WHERE id=? AND video_id=?"
          )
          .bind(
            rid,
            pvrd[1]
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

      if (
        String(r.user_id) !==
          String(user.id) &&
        String(
          user.username
        ).toLowerCase() !==
          "fazmen"
      ) {
        return json(
          {
            error:
              "Kamu tidak memiliki izin untuk menghapus reply ini."
          },
          403
        );
      }

      await env.DB
        .prepare(
          "DELETE FROM public_video_replies WHERE id=?"
        )
        .bind(rid)
        .run();

      return json({
        ok: true,
        deleted: true,
        replyId: rid
      });
    }

    // ============================================================
    // GLOBAL COMMENTS
    // ============================================================

    if (
      route === "/comments" &&
      method === "GET"
    ) {
      await ensureGlobalCommentSchema(
        env
      );

      const result =
        await env.DB
          .prepare(
            `SELECT
              c.id,
              c.user_id AS userId,
              c.username,
              c.comment,
              c.created_at AS createdAt,
              c.updated_at AS updatedAt,

              (
                SELECT COUNT(*)
                FROM comment_likes l
                WHERE l.comment_id=c.id
              ) AS likes,

              ${
                user
                  ? "EXISTS(SELECT 1 FROM comment_likes l WHERE l.comment_id=c.id AND l.user_id=?)"
                  : "0"
              } AS liked

            FROM comments c
            ORDER BY c.created_at DESC`
          )
          .bind(
            ...(user
              ? [user.id]
              : [])
          )
          .all();

      const repliesResult =
        await env.DB
          .prepare(
            "SELECT id,comment_id AS commentId,user_id AS userId,username,reply,created_at AS createdAt,updated_at AS updatedAt FROM comment_replies ORDER BY created_at ASC"
          )
          .all();

      const replyMap =
        new Map();

      for (
        const r of
          repliesResult.results ||
          []
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

      return json({
        ok: true,
        comments:
          (result.results || [])
            .map(c => ({
              ...c,
              liked: !!c.liked,
              replies:
                replyMap.get(
                  c.id
                ) || []
            }))
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

      await ensureGlobalCommentSchema(
        env
      );

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

      if (comment.length > 2000) {
        return json(
          {
            error:
              "Komentar maksimal 2000 karakter."
          },
          400
        );
      }

      const cid =
        id("comment");

      const ts = now();

      await env.DB
        .prepare(
          "INSERT INTO comments(id,user_id,username,comment,created_at,updated_at) VALUES(?,?,?,?,?,?)"
        )
        .bind(
          cid,
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
            id: cid,
            userId: user.id,
            username:
              user.username,
            comment,
            createdAt: ts,
            updatedAt: ts,
            likes: 0,
            liked: false,
            replies: []
          }
        },
        201
      );
    }

    const glike =
      route.match(
        /^\/comments\/([^/]+)\/like$/
      );

    if (
      glike &&
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

      await ensureGlobalCommentSchema(
        env
      );

      const cid =
        glike[1];

      const c =
        await env.DB
          .prepare(
            "SELECT id FROM comments WHERE id=?"
          )
          .bind(cid)
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

      const old =
        await env.DB
          .prepare(
            "SELECT comment_id FROM comment_likes WHERE comment_id=? AND user_id=?"
          )
          .bind(
            cid,
            user.id
          )
          .first();

      if (old) {
        await env.DB
          .prepare(
            "DELETE FROM comment_likes WHERE comment_id=? AND user_id=?"
          )
          .bind(
            cid,
            user.id
          )
          .run();
      } else {
        await env.DB
          .prepare(
            "INSERT INTO comment_likes(comment_id,user_id,created_at) VALUES(?,?,?)"
          )
          .bind(
            cid,
            user.id,
            now()
          )
          .run();
      }

      const count =
        await env.DB
          .prepare(
            "SELECT COUNT(*) AS n FROM comment_likes WHERE comment_id=?"
          )
          .bind(cid)
          .first();

      return json({
        ok: true,
        liked: !old,
        likes:
          Number(count?.n) || 0
      });
    }

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

      await ensureGlobalCommentSchema(
        env
      );

      const cid =
        route.split("/")[2];

      const parent =
        await env.DB
          .prepare(
            "SELECT id FROM comments WHERE id=?"
          )
          .bind(cid)
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

      if (reply.length > 2000) {
        return json(
          {
            error:
              "Balasan maksimal 2000 karakter."
          },
          400
        );
      }

      const rid =
        id("reply");

      const ts = now();

      await env.DB
        .prepare(
          "INSERT INTO comment_replies(id,comment_id,user_id,username,reply,created_at,updated_at) VALUES(?,?,?,?,?,?,?)"
        )
        .bind(
          rid,
          cid,
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
            id: rid,
            commentId: cid,
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

      await ensureGlobalCommentSchema(
        env
      );

      const rid =
        route.split("/")[3];

      const r =
        await env.DB
          .prepare(
            "SELECT id,user_id FROM comment_replies WHERE id=?"
          )
          .bind(rid)
          .first();

      if (!r) {
        return json(
          {
            error:
              "Balasan tidak ditemukan."
          },
          404
        );
      }

      if (
        String(r.user_id) !==
          String(user.id) &&
        String(
          user.username
        ).toLowerCase() !==
          "fazmen"
      ) {
        return json(
          {
            error:
              "Kamu tidak memiliki izin untuk menghapus balasan ini."
          },
          403
        );
      }

      await env.DB
        .prepare(
          "DELETE FROM comment_reply_likes WHERE reply_id=?"
        )
        .bind(rid)
        .run();

      await env.DB
        .prepare(
          "DELETE FROM comment_replies WHERE id=?"
        )
        .bind(rid)
        .run();

      return json({
        ok: true,
        deleted: true,
        replyId: rid
      });
    }

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

      await ensureGlobalCommentSchema(
        env
      );

      const cid =
        route.split("/")[2];

      const c =
        await env.DB
          .prepare(
            "SELECT id,user_id FROM comments WHERE id=?"
          )
          .bind(cid)
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

      if (
        String(c.user_id) !==
          String(user.id) &&
        String(
          user.username
        ).toLowerCase() !==
          "fazmen"
      ) {
        return json(
          {
            error:
              "Kamu tidak memiliki izin untuk menghapus komentar ini."
          },
          403
        );
      }

      await env.DB.batch([
        env.DB
          .prepare(
            "DELETE FROM comment_likes WHERE comment_id=?"
          )
          .bind(cid),

        env.DB
          .prepare(
            "DELETE FROM comment_replies WHERE comment_id=?"
          )
          .bind(cid),

        env.DB
          .prepare(
            "DELETE FROM comments WHERE id=?"
          )
          .bind(cid)
      ]);

      return json({
        ok: true,
        deleted: true,
        commentId: cid
      });
    }

    // ============================================================
    // DELETE ACCOUNT
    // ============================================================

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

      await ensureGlobalCommentSchema(
        env
      );

      await env.DB.batch([
        env.DB
          .prepare(
            "DELETE FROM video_progress WHERE user_id=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM user_data WHERE user_id=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM public_video_reactions WHERE user_id=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM public_video_notes WHERE user_id=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM public_video_comment_likes WHERE user_id=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM public_video_comments WHERE user_id=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM public_video_replies WHERE user_id=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM comment_likes WHERE user_id=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM comment_reply_likes WHERE user_id=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM comment_replies WHERE user_id=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM comments WHERE user_id=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM public_video_replies WHERE video_id IN (SELECT id FROM public_videos WHERE COALESCE(user_id,owner_id)=?)"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM public_video_comments WHERE video_id IN (SELECT id FROM public_videos WHERE COALESCE(user_id,owner_id)=?)"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM public_video_reactions WHERE video_id IN (SELECT id FROM public_videos WHERE COALESCE(user_id,owner_id)=?)"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM public_video_views WHERE video_id IN (SELECT id FROM public_videos WHERE COALESCE(user_id,owner_id)=?)"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM public_video_notes WHERE video_id IN (SELECT id FROM public_videos WHERE COALESCE(user_id,owner_id)=?)"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM public_videos WHERE COALESCE(user_id,owner_id)=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM sessions WHERE user_id=?"
          )
          .bind(user.id),

        env.DB
          .prepare(
            "DELETE FROM users WHERE id=?"
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
            clearCookie(
              "funlearn_session"
            )
        }
      );
    }

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

      const state =
        await readState(
          env,
          user.id
        );

      state.onlineProgress = {
        ...(state.onlineProgress || {}),
        [String(
          body.moduleId
        )]: body
      };

      await writeState(
        env,
        user.id,
        state
      );

      return json({
        ok: true
      });
    }

    return json(
      {
        error: "Not found"
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

async function createSession(
  env,
  userId,
  username
) {
  const raw =
    b64(randomBytes(32));

  const sid =
    await hashToken(raw);

  const expires =
    new Date(
      Date.now() +
        SESSION_DAYS *
          86400000
    ).toISOString();

  await env.DB
    .prepare(
      "INSERT INTO sessions(id_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)"
    )
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
          SESSION_DAYS * 86400
        )
    }
  );
}
