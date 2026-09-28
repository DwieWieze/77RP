import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

const seedData = {};

const authStore = getStore({ name: 'mapka-auth', consistency: 'strong' });
const mapsStore = getStore({ name: 'mapka-maps', consistency: 'strong' });
const imagesStore = getStore({ name: 'mapka-images', consistency: 'strong' });
const emptyMap = () => ({ version: 3, zones: {}, markers: [], npcs: [], gridSize: 5, highlightColor: '#21b889' });
const jsonHeaders = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };

function reply(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: { ...jsonHeaders, ...headers } });
}
function fail(message, status = 400) { throw Object.assign(new Error(message), { status }); }
function cleanState(value) {
  const state = value && typeof value === 'object' ? value : {};
  state.users = Array.isArray(state.users) ? state.users : [];
  state.groups = Array.isArray(state.groups) ? state.groups : [];
  state.sessions = Array.isArray(state.sessions) ? state.sessions.filter(session => session.expires > Date.now()) : [];
  return state;
}
async function readState() { return cleanState(await authStore.get('state', { type: 'json' })); }
async function mutateState(change) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const entry = await authStore.getWithMetadata('state', { type: 'json' });
    const state = cleanState(entry?.data);
    const result = await change(state);
    try {
      if (entry) await authStore.setJSON('state', state, { onlyIfMatch: entry.etag });
      else await authStore.setJSON('state', state, { onlyIfNew: true });
      return result;
    } catch (error) {
      if (attempt === 4) throw error;
    }
  }
}
function normalizeUsername(value) { return String(value || '').trim().toLocaleLowerCase('pl-PL'); }
function publicUser(user) { return { id: user.id, username: user.username }; }
function hashPassword(password, salt) { return crypto.scryptSync(password, salt, 64).toString('hex'); }
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function safeEqual(a, b) {
  try { return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')); }
  catch { return false; }
}
function parseCookies(request) {
  return Object.fromEntries(String(request.headers.get('cookie') || '').split(';').map(item => item.trim()).filter(Boolean).map(item => {
    const index = item.indexOf('=');
    return [decodeURIComponent(item.slice(0, index)), decodeURIComponent(item.slice(index + 1))];
  }));
}
function findUser(request, state) {
  const token = parseCookies(request).mapka_session;
  if (!token) return null;
  const session = state.sessions.find(item => item.tokenHash === tokenHash(token) && item.expires > Date.now());
  return session && state.users.find(user => user.id === session.userId);
}
function requireUser(request, state) { return findUser(request, state) || fail('Zaloguj się, aby korzystać z mapy.', 401); }
function requireGroup(state, user, groupId) {
  return state.groups.find(group => group.id === groupId && group.members.includes(user.id)) || fail('Nie masz dostępu do tej grupy.', 403);
}
function groupView(group, state, user) {
  return {
    id: group.id,
    name: group.name,
    owner: group.ownerId === user.id,
    members: group.members.map(id => state.users.find(item => item.id === id)).filter(Boolean).map(publicUser)
  };
}
function createSession(state, userId) {
  state.sessions = state.sessions.filter(session => session.userId !== userId && session.expires > Date.now());
  const token = crypto.randomBytes(32).toString('hex');
  state.sessions.push({ tokenHash: tokenHash(token), userId, expires: Date.now() + 30 * 24 * 60 * 60 * 1000 });
  return token;
}
function sessionCookie(request, token, maxAge = 2592000) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `mapka_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}`;
}
function validateMap(value) {
  if (!value || typeof value !== 'object' || !value.zones || typeof value.zones !== 'object' || !Array.isArray(value.markers)) fail('Nieprawidłowe dane mapy.');
  return { ...emptyMap(), ...value, version: 3, gridSize: 5, npcs: [] };
}
async function requestJson(request) {
  try { return await request.json(); }
  catch { return fail('Nieprawidłowe dane formularza.'); }
}
function apiPath(request) { return decodeURIComponent(new URL(request.url).pathname); }

export default async (request) => {
  try {
    const path = apiPath(request);
    const method = request.method;

    if (path === '/api/register' && method === 'POST') {
      const payload = await requestJson(request);
      const username = String(payload.username || '').trim();
      if (!/^[\p{L}\p{N}_-]{3,24}$/u.test(username)) fail('Nazwa musi mieć 3–24 znaki: litery, cyfry, _ lub -.');
      if (String(payload.password || '').length < 6) fail('Hasło musi mieć co najmniej 6 znaków.');
      const created = await mutateState(async state => {
        const normalized = normalizeUsername(username);
        if (state.users.some(user => user.normalized === normalized)) fail('Ta nazwa użytkownika jest już zajęta.', 409);
        const salt = crypto.randomBytes(16).toString('hex');
        const user = { id: crypto.randomUUID(), username, normalized, salt, passwordHash: hashPassword(String(payload.password), salt), createdAt: new Date().toISOString() };
        const firstUser = state.users.length === 0;
        state.users.push(user);
        const group = { id: crypto.randomUUID(), name: `Mapa ${username}`, ownerId: user.id, members: [user.id], createdAt: new Date().toISOString() };
        state.groups.push(group);
        return { user, group, firstUser, token: createSession(state, user.id), state };
      });
      await mapsStore.setJSON(created.group.id, created.firstUser && seedData && typeof seedData === 'object' ? { ...emptyMap(), ...seedData, version: 3 } : emptyMap());
      return reply({ user: publicUser(created.user), groups: [groupView(created.group, created.state, created.user)] }, 201, { 'set-cookie': sessionCookie(request, created.token) });
    }

    if (path === '/api/login' && method === 'POST') {
      const payload = await requestJson(request);
      const loggedIn = await mutateState(async state => {
        const user = state.users.find(item => item.normalized === normalizeUsername(payload.username));
        if (!user || !safeEqual(hashPassword(String(payload.password || ''), user.salt), user.passwordHash)) fail('Nieprawidłowa nazwa użytkownika lub hasło.', 401);
        return { user, token: createSession(state, user.id) };
      });
      return reply({ user: publicUser(loggedIn.user) }, 200, { 'set-cookie': sessionCookie(request, loggedIn.token) });
    }

    if (path === '/api/logout' && method === 'POST') {
      const rawToken = parseCookies(request).mapka_session;
      if (rawToken) await mutateState(async state => { state.sessions = state.sessions.filter(session => session.tokenHash !== tokenHash(rawToken)); });
      return reply({ ok: true }, 200, { 'set-cookie': sessionCookie(request, '', 0) });
    }

    if (path === '/api/auth' && method === 'GET') {
      const state = await readState(); const user = findUser(request, state);
      return reply(user ? { user: publicUser(user) } : { user: null });
    }

    if (path === '/api/groups' && method === 'GET') {
      const state = await readState(); const user = requireUser(request, state);
      return reply(state.groups.filter(group => group.members.includes(user.id)).map(group => groupView(group, state, user)));
    }

    if (path === '/api/groups' && method === 'POST') {
      const payload = await requestJson(request); const name = String(payload.name || '').trim();
      if (name.length < 2 || name.length > 40) fail('Nazwa grupy musi mieć 2–40 znaków.');
      const created = await mutateState(async state => {
        const user = requireUser(request, state);
        const group = { id: crypto.randomUUID(), name, ownerId: user.id, members: [user.id], createdAt: new Date().toISOString() };
        state.groups.push(group); return { group, user, state };
      });
      await mapsStore.setJSON(created.group.id, emptyMap());
      return reply(groupView(created.group, created.state, created.user), 201);
    }

    const memberMatch = /^\/api\/groups\/([^/]+)\/members$/.exec(path);
    if (memberMatch && method === 'POST') {
      const payload = await requestJson(request);
      const view = await mutateState(async state => {
        const user = requireUser(request, state); const group = requireGroup(state, user, memberMatch[1]);
        if (group.ownerId !== user.id) fail('Tylko właściciel grupy może dodawać osoby.', 403);
        const invited = state.users.find(item => item.normalized === normalizeUsername(payload.username));
        if (!invited) fail('Nie znaleziono użytkownika o tej nazwie.', 404);
        if (!group.members.includes(invited.id)) group.members.push(invited.id);
        return groupView(group, state, user);
      });
      return reply(view);
    }

    const dataMatch = /^\/api\/groups\/([^/]+)\/data$/.exec(path);
    if (dataMatch && method === 'GET') {
      const state = await readState(); const user = requireUser(request, state); requireGroup(state, user, dataMatch[1]);
      return reply(await mapsStore.get(dataMatch[1], { type: 'json' }) || emptyMap());
    }
    if (dataMatch && method === 'POST') {
      const state = await readState(); const user = requireUser(request, state); requireGroup(state, user, dataMatch[1]);
      await mapsStore.setJSON(dataMatch[1], validateMap(await requestJson(request)));
      return reply({ ok: true });
    }

    const imagesMatch = /^\/api\/groups\/([^/]+)\/images$/.exec(path);
    if (imagesMatch && method === 'GET') {
      const state = await readState(); const user = requireUser(request, state); requireGroup(state, user, imagesMatch[1]);
      const listed = await imagesStore.list({ prefix: `${imagesMatch[1]}/` });
      return reply(listed.blobs.map(blob => `/group-images/${encodeURIComponent(blob.key.split('/')[0])}/${encodeURIComponent(blob.key.slice(blob.key.indexOf('/') + 1))}`).sort());
    }

    const uploadMatch = /^\/api\/groups\/([^/]+)\/upload$/.exec(path);
    if (uploadMatch && method === 'POST') {
      const state = await readState(); const user = requireUser(request, state); requireGroup(state, user, uploadMatch[1]);
      const payload = await requestJson(request);
      const match = /^data:image\/([a-zA-Z0-9.+-]+);base64,(.+)$/.exec(payload.data || '');
      if (!match) fail('Nieprawidłowy plik obrazu.');
      const extensions = { jpeg: '.jpg', jpg: '.jpg', png: '.png', webp: '.webp', gif: '.gif', bmp: '.bmp' };
      const subtype = match[1].toLowerCase(); const extension = extensions[subtype];
      if (!extension) fail('Nieobsługiwany format zdjęcia.');
      const content = Buffer.from(match[2], 'base64');
      if (content.length > 3 * 1024 * 1024) fail('Zdjęcie może mieć maksymalnie 3 MB.', 413);
      const base = String(payload.name || 'photo').replace(/\.[^.]+$/, '').replace(/[^a-zA-Z0-9_-]/g, '-') || 'photo';
      const name = `${base}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}${extension}`;
      await imagesStore.set(`${uploadMatch[1]}/${name}`, content.buffer.slice(content.byteOffset, content.byteOffset + content.byteLength), { metadata: { contentType: `image/${subtype === 'jpg' ? 'jpeg' : subtype}` } });
      return reply({ path: `/group-images/${encodeURIComponent(uploadMatch[1])}/${encodeURIComponent(name)}` });
    }

    const imageMatch = /^\/group-images\/([^/]+)\/(.+)$/.exec(path);
    if (imageMatch && method === 'GET') {
      const state = await readState(); const user = requireUser(request, state); requireGroup(state, user, imageMatch[1]);
      const entry = await imagesStore.getWithMetadata(`${imageMatch[1]}/${imageMatch[2]}`, { type: 'arrayBuffer' });
      if (!entry) return new Response('Nie znaleziono zdjęcia.', { status: 404 });
      return new Response(entry.data, { headers: { 'content-type': entry.metadata?.contentType || 'application/octet-stream', 'cache-control': 'private, max-age=3600', 'x-content-type-options': 'nosniff' } });
    }

    return reply({ error: 'Nie znaleziono endpointu.' }, 404);
  } catch (error) {
    if (!error.status || error.status >= 500) console.error(error);
    return reply({ error: error.status ? error.message : 'Wewnętrzny błąd serwera.' }, error.status || 500);
  }
};

export const config = {
  path: ['/api/*', '/group-images/*']
};
