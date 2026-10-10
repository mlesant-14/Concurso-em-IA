// Servidor do Estuda AI — Node 22+ (usa node:sqlite embutido, sem dependências)
// Rodar:  node server.js   → http://localhost:3000
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const db = new DatabaseSync(path.join(__dirname, 'estuda-ai.db'));
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, nome TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  senha_hash TEXT NOT NULL, salt TEXT NOT NULL, criado_em TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  criado_em TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS kv(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  k TEXT NOT NULL, v TEXT NOT NULL, PRIMARY KEY(user_id,k));
CREATE TABLE IF NOT EXISTS questoes(
  id INTEGER PRIMARY KEY, banca TEXT NOT NULL, materia TEXT NOT NULL,
  enunciado TEXT NOT NULL, alternativas TEXT NOT NULL, correta INTEGER NOT NULL,
  explicacao TEXT, origem TEXT DEFAULT 'ia', criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(banca,materia,enunciado));
CREATE INDEX IF NOT EXISTS idx_q ON questoes(banca,materia);
`);

const q = {
  addUser: db.prepare('INSERT INTO users(nome,email,senha_hash,salt) VALUES(?,?,?,?)'),
  userByEmail: db.prepare('SELECT * FROM users WHERE email=?'),
  addSession: db.prepare('INSERT INTO sessions(token,user_id) VALUES(?,?)'),
  delSession: db.prepare('DELETE FROM sessions WHERE token=?'),
  userByToken: db.prepare('SELECT u.id,u.nome,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?'),
  kvAll: db.prepare('SELECT k,v FROM kv WHERE user_id=?'),
  kvSet: db.prepare('INSERT INTO kv(user_id,k,v) VALUES(?,?,?) ON CONFLICT(user_id,k) DO UPDATE SET v=excluded.v'),
  kvClear: db.prepare('DELETE FROM kv WHERE user_id=?'),
  qGet: db.prepare('SELECT * FROM questoes WHERE banca=? AND materia=? ORDER BY RANDOM() LIMIT ?'),
  qAdd: db.prepare('INSERT OR IGNORE INTO questoes(banca,materia,enunciado,alternativas,correta,explicacao) VALUES(?,?,?,?,?,?)'),
};

const hash = (senha, salt) => crypto.scryptSync(senha, salt, 64).toString('hex');
const KEYS = new Set(['cfg', 'cards', 'stats', 'prof', 'dark']);

function readBody(req) {
  return new Promise((ok, no) => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 5e6) { req.destroy(); no(new Error('Corpo muito grande')); } });
    req.on('end', () => { try { ok(d ? JSON.parse(d) : {}); } catch (e) { no(e); } });
  });
}
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const newSession = userId => { const t = crypto.randomBytes(32).toString('hex'); q.addSession.run(t, userId); return t; };

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
      try { id = Number(q.addUser.run(nome.trim(), email.trim().toLowerCase(), hash(senha, salt), salt).lastInsertRowid); }
      catch { return send(res, 409, { erro: 'E-mail já cadastrado.' }); }
      return send(res, 200, { token: newSession(id), nome: nome.trim() });
    }
    if (req.method === 'POST' && p === '/api/login') {
      const { email, senha } = await readBody(req);
      const u = q.userByEmail.get((email || '').trim().toLowerCase());
      const ok = u && crypto.timingSafeEqual(Buffer.from(hash(senha || '', u.salt), 'hex'), Buffer.from(u.senha_hash, 'hex'));
      if (!ok) return send(res, 401, { erro: 'E-mail ou senha incorretos.' });
      return send(res, 200, { token: newSession(u.id), nome: u.nome });
    }

    // ---------- rotas autenticadas ----------
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const user = token && q.userByToken.get(token);
    if (!user) return send(res, 401, { erro: 'Sessão inválida.' });

    if (req.method === 'POST' && p === '/api/logout') { q.delSession.run(token); return send(res, 200, {}); }

    if (req.method === 'GET' && p === '/api/state') {
      const st = {}; for (const r of q.kvAll.all(user.id)) st[r.k] = JSON.parse(r.v);
      return send(res, 200, { user, state: st });
    }
    if (req.method === 'PUT' && p.startsWith('/api/kv/')) {
      const k = decodeURIComponent(p.slice(8));
      if (!KEYS.has(k)) return send(res, 400, { erro: 'Chave inválida' });
      q.kvSet.run(user.id, k, JSON.stringify((await readBody(req)).v ?? null));
      return send(res, 200, {});
    }
    if (req.method === 'DELETE' && p === '/api/state') { q.kvClear.run(user.id); return send(res, 200, {}); }

    // ---------- banco de questões compartilhado ----------
    if (req.method === 'GET' && p === '/api/questoes') {
      const n = Math.min(30, +url.searchParams.get('n') || 10);
      const rows = q.qGet.all(url.searchParams.get('banca') || '', url.searchParams.get('materia') || '', n);
      return send(res, 200, rows.map(r => ({ enunciado: r.enunciado, alternativas: JSON.parse(r.alternativas), correta: r.correta, explicacao: r.explicacao })));
    }
    if (req.method === 'POST' && p === '/api/questoes') {
      const { banca, materia, questoes } = await readBody(req);
      let novas = 0;
      db.exec('BEGIN');
      for (const x of questoes || []) {
        if (!x.enunciado || !Array.isArray(x.alternativas) || !Number.isInteger(x.correta)) continue;
        novas += Number(q.qAdd.run(banca, materia, x.enunciado, JSON.stringify(x.alternativas), x.correta, x.explicacao || '').changes);
      }
      db.exec('COMMIT');
      return send(res, 200, { novas });
    }
    send(res, 404, { erro: 'Rota inexistente' });
  } catch (e) { try { db.exec('ROLLBACK'); } catch {} send(res, 500, { erro: e.message }); }
});

server.listen(PORT, '0.0.0.0', () => console.log(`Estuda AI rodando na porta ${PORT}`));
