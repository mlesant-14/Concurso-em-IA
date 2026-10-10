// Servidor do Estuda AI — Suporte a Turso Cloud e SQLite local
// Rodar:  node server.js   → http://localhost:3000
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { createClient } = require('@libsql/client');

// Carrega .env nativamente se existir
try { if (typeof process.loadEnvFile === 'function') process.loadEnvFile(); } catch {}

const PORT = process.env.PORT || 3000;
const dbUrl = process.env.TURSO_DATABASE_URL || 'file:estuda-ai.db';
const dbAuthToken = process.env.TURSO_AUTH_TOKEN;

const db = createClient({
  url: dbUrl,
  authToken: dbAuthToken,
});

async function initDb() {
  await db.executeMultiple(`
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      senha_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      criado_em TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS sessions(
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      criado_em TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS kv(
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      k TEXT NOT NULL,
      v TEXT NOT NULL,
      PRIMARY KEY(user_id, k)
    );
    CREATE TABLE IF NOT EXISTS questoes(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      banca TEXT NOT NULL,
      materia TEXT NOT NULL,
      enunciado TEXT NOT NULL,
      alternativas TEXT NOT NULL,
      correta INTEGER NOT NULL,
      explicacao TEXT,
      origem TEXT DEFAULT 'ia',
      criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(banca, materia, enunciado)
    );
    CREATE INDEX IF NOT EXISTS idx_q ON questoes(banca, materia);
  `);
}

const hash = (senha, salt) => crypto.scryptSync(senha, salt, 64).toString('hex');
const KEYS = new Set(['cfg', 'cards', 'stats', 'prof', 'dark']);

function readBody(req) {
  return new Promise((ok, no) => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 5e6) { req.destroy(); no(new Error('Corpo muito grande')); } });
    req.on('end', () => { try { ok(d ? JSON.parse(d) : {}); } catch (e) { no(e); } });
  });
}

const send = (res, code, obj) => {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
};

const newSession = async userId => {
  const t = crypto.randomBytes(32).toString('hex');
  await db.execute({
    sql: 'INSERT INTO sessions(token, user_id) VALUES(?, ?)',
    args: [t, userId]
  });
  return t;
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  try {
    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(path.join(__dirname, 'estuda-ai.html')));
    }
    if (!p.startsWith('/api/')) return send(res, 404, { erro: 'Não encontrado' });

    // ---------- autenticação ----------
    if (req.method === 'POST' && p === '/api/register') {
      const { nome, email, senha } = await readBody(req);
      if (!nome || !/^\S+@\S+\.\S+$/.test(email || '') || (senha || '').length < 6)
        return send(res, 400, { erro: 'Informe nome, e-mail válido e senha (mín. 6 caracteres).' });
      const salt = crypto.randomBytes(16).toString('hex');
      let id;
      try {
        const ins = await db.execute({
          sql: 'INSERT INTO users(nome, email, senha_hash, salt) VALUES(?, ?, ?, ?)',
          args: [nome.trim(), email.trim().toLowerCase(), hash(senha, salt), salt]
        });
        id = Number(ins.lastInsertRowid);
      } catch {
        return send(res, 409, { erro: 'E-mail já cadastrado.' });
      }
      const token = await newSession(id);
      return send(res, 200, { token, nome: nome.trim() });
    }

    if (req.method === 'POST' && p === '/api/login') {
      const { email, senha } = await readBody(req);
      const resUser = await db.execute({
        sql: 'SELECT * FROM users WHERE email=?',
        args: [(email || '').trim().toLowerCase()]
      });
      const u = resUser.rows[0];
      const ok = u && crypto.timingSafeEqual(Buffer.from(hash(senha || '', u.salt), 'hex'), Buffer.from(u.senha_hash, 'hex'));
      if (!ok) return send(res, 401, { erro: 'E-mail ou senha incorretos.' });
      const token = await newSession(u.id);
      return send(res, 200, { token, nome: u.nome });
    }

    // ---------- rotas autenticadas ----------
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    let user = null;
    if (token) {
      const resSess = await db.execute({
        sql: 'SELECT u.id, u.nome, u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?',
        args: [token]
      });
      user = resSess.rows[0] || null;
    }
    if (!user) return send(res, 401, { erro: 'Sessão inválida.' });

    if (req.method === 'POST' && p === '/api/logout') {
      await db.execute({ sql: 'DELETE FROM sessions WHERE token=?', args: [token] });
      return send(res, 200, {});
    }

    if (req.method === 'GET' && p === '/api/state') {
      const resKv = await db.execute({
        sql: 'SELECT k, v FROM kv WHERE user_id=?',
        args: [user.id]
      });
      const st = {};
      for (const r of resKv.rows) {
        try { st[r.k] = JSON.parse(r.v); } catch {}
      }
      return send(res, 200, { user, state: st });
    }

    if (req.method === 'PUT' && p.startsWith('/api/kv/')) {
      const k = decodeURIComponent(p.slice(8));
      if (!KEYS.has(k)) return send(res, 400, { erro: 'Chave inválida' });
      await db.execute({
        sql: 'INSERT INTO kv(user_id, k, v) VALUES(?, ?, ?) ON CONFLICT(user_id, k) DO UPDATE SET v=excluded.v',
        args: [user.id, k, JSON.stringify((await readBody(req)).v ?? null)]
      });
      return send(res, 200, {});
    }

    if (req.method === 'DELETE' && p === '/api/state') {
      await db.execute({ sql: 'DELETE FROM kv WHERE user_id=?', args: [user.id] });
      return send(res, 200, {});
    }

    // ---------- banco de questões compartilhado ----------
    if (req.method === 'GET' && p === '/api/questoes') {
      const n = Math.min(30, +url.searchParams.get('n') || 10);
      const resQ = await db.execute({
        sql: 'SELECT * FROM questoes WHERE banca=? AND materia=? ORDER BY RANDOM() LIMIT ?',
        args: [url.searchParams.get('banca') || '', url.searchParams.get('materia') || '', n]
      });
      return send(res, 200, resQ.rows.map(r => ({
        enunciado: r.enunciado,
        alternativas: typeof r.alternativas === 'string' ? JSON.parse(r.alternativas) : r.alternativas,
        correta: Number(r.correta),
        explicacao: r.explicacao
      })));
    }

    if (req.method === 'POST' && p === '/api/questoes') {
      const { banca, materia, questoes } = await readBody(req);
      const stmts = [];
      for (const x of questoes || []) {
        if (!x.enunciado || !Array.isArray(x.alternativas) || !Number.isInteger(x.correta)) continue;
        stmts.push({
          sql: 'INSERT OR IGNORE INTO questoes(banca, materia, enunciado, alternativas, correta, explicacao) VALUES(?,?,?,?,?,?)',
          args: [banca, materia, x.enunciado, JSON.stringify(x.alternativas), x.correta, x.explicacao || '']
        });
      }
      let novas = 0;
      if (stmts.length > 0) {
        const batchRes = await db.batch(stmts, 'write');
        for (const r of batchRes) novas += Number(r.rowsAffected || 0);
      }
      return send(res, 200, { novas });
    }

    send(res, 404, { erro: 'Rota inexistente' });
  } catch (e) {
    send(res, 500, { erro: e.message });
  }
});

initDb().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Estuda AI rodando na porta ${PORT} [Banco: ${process.env.TURSO_DATABASE_URL ? 'Turso Cloud' : 'Local SQLite'}]`);
  });
}).catch(err => {
  console.error('Erro ao inicializar o banco:', err);
  process.exit(1);
});
