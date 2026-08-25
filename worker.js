/**
 * TRANSAC'IMMO — comptes agents, sessions et stockage des dossiers.
 *
 * S'execute AVANT que le moindre fichier ne soit servi
 * (grace a "run_worker_first": true dans wrangler.jsonc).
 *
 * ------------------------------------------------------------------
 * VARIABLES A DEFINIR DANS CLOUDFLARE (Settings > Variables et secrets)
 *   ADMIN_USER     = ton identifiant de direction   (type : Secret)
 *   ADMIN_PASS     = ton mot de passe de direction  (type : Secret)
 *   SESSION_SECRET = une longue phrase au hasard    (type : Secret)
 *
 * ESPACE KV a brancher sous le nom DB.
 * ------------------------------------------------------------------
 *
 * Structure du stockage :
 *   user:<login>  -> {nom, role:'agent'|'admin', sel, hash, cree}
 *   crm:<login>   -> {v, updated, projects[], agents}
 *
 * Les mots de passe ne sont JAMAIS stockes en clair : uniquement
 * une empreinte PBKDF2 (100 000 iterations) accompagnee d'un sel unique.
 */

const JSONH = { 'Content-Type': 'application/json; charset=UTF-8', 'Cache-Control': 'no-store' };
const rep = (o, s) => new Response(JSON.stringify(o), { status: s || 200, headers: JSONH });

/* ---------- Outils cryptographiques ---------- */
const enc = new TextEncoder();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64url = buf => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function alea(n) {
  return b64url(crypto.getRandomValues(new Uint8Array(n || 16)));
}

async function empreinte(mdp, sel) {
  const cle = await crypto.subtle.importKey('raw', enc.encode(mdp), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(sel), iterations: 100000, hash: 'SHA-256' }, cle, 256);
  return b64(bits);
}

// Comparaison a duree constante : ne renseigne pas un attaquant sur
// le nombre de caracteres corrects (attaque temporelle).
function egal(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function signer(txt, secret) {
  const cle = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', cle, enc.encode(txt)));
}

function secretSession(env) {
  return env.SESSION_SECRET || ((env.ADMIN_PASS || 'transac') + '|' + (env.ADMIN_USER || 'admin'));
}

/* ---------- Sessions (cookie signe) ---------- */
async function creerJeton(env, login, role, nom) {
  const corps = b64url(enc.encode(JSON.stringify({
    u: login, r: role, n: nom || '', exp: Date.now() + 30 * 86400000
  })));
  return corps + '.' + await signer(corps, secretSession(env));
}

async function lireJeton(env, jeton) {
  if (!jeton || jeton.indexOf('.') < 0) return null;
  const [corps, sig] = jeton.split('.');
  if (!egal(sig, await signer(corps, secretSession(env)))) return null;   // signature forgee
  try {
    const o = JSON.parse(atob(corps.replace(/-/g, '+').replace(/_/g, '/')));
    if (!o.exp || o.exp < Date.now()) return null;                        // session expiree
    return o;
  } catch (e) { return null; }
}

function cookieDe(request, nom) {
  const c = request.headers.get('Cookie') || '';
  const m = c.match(new RegExp('(?:^|;\\s*)' + nom + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : '';
}

async function session(request, env) {
  return await lireJeton(env, cookieDe(request, 'ti_session'));
}

/* ---------- Comptes ---------- */
async function lireCompte(env, login) {
  const v = await env.DB.get('user:' + login);
  return v ? JSON.parse(v) : null;
}

async function verifier(env, login, mdp) {
  // Compte de direction issu des variables Cloudflare : toujours valable,
  // meme si le stockage est vide. C'est le filet de securite anti-blocage.
  // .trim() : un secret colle dans Cloudflare traine souvent une espace ou
  // un retour a la ligne invisible.
  const aUser = String(env.ADMIN_USER || '').trim();
  const aPass = String(env.ADMIN_PASS || '').trim();
  if (aUser && aPass && egal(login, nettoyerLogin(aUser)) && egal(String(mdp).trim(), aPass)) {
    return { login: nettoyerLogin(aUser), role: 'admin', nom: 'Direction' };
  }
  const c = await lireCompte(env, login);
  if (!c) return null;
  const h = await empreinte(mdp, c.sel);
  if (!egal(h, c.hash)) return null;
  return { login, role: c.role || 'agent', nom: c.nom || login };
}

// Un identifiant est ramene a une forme unique : minuscules, sans accent.
// On applique EXACTEMENT la meme regle des deux cotes de la comparaison,
// sinon un ADMIN_USER avec une majuscule ou un @ ne matche jamais.
const nettoyerLogin = s => String(s || '').trim().toLowerCase()
  .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
  .replace(/[^a-z0-9._@-]/g, '');

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;

    /* ============ Diagnostic ============ */
    // Ne renvoie que des oui/non : aucune valeur de variable n'est exposee.
    if (p === '/api/etat') {
      let comptes = 0;
      if (env.DB) { try { comptes = (await env.DB.list({ prefix: 'user:' })).keys.length; } catch (e) { } }
      const aUser = String(env.ADMIN_USER || '').trim();
      return rep({
        stockage: !!env.DB,
        adminConfigure: !!(env.ADMIN_USER && env.ADMIN_PASS),
        secretSession: !!env.SESSION_SECRET,
        comptesAgents: comptes,
        // Aide au diagnostic, sans divulguer la valeur :
        adminLongueur: aUser.length,                             // 0 si vide
        adminNormalise: aUser === nettoyerLogin(aUser),          // false = majuscules/accents/espaces
        adminEspaces: aUser !== String(env.ADMIN_USER || ''),    // true = espace parasite dans la variable
        motDePasseEspaces: String(env.ADMIN_PASS || '') !== String(env.ADMIN_PASS || '').trim()
      });
    }

    /* ============ Relais DVF ============ */
    // Les fichiers publics DVF (files.data.gouv.fr) sont bloques par CORS dans
    // le navigateur : on les sert d'ici, avec cache. Donnees publiques, aucune
    // authentification necessaire. Seul ce domaine precis est relayable.
    if (p === '/api/dvfcsv') {
      const cible = url.searchParams.get('u') || '';
      if (!cible.startsWith('https://files.data.gouv.fr/geo-dvf/')) {
        return new Response('domaine non autorise', { status: 400 });
      }
      const r = await fetch(cible, { cf: { cacheTtl: 86400, cacheEverything: true } });
      if (!r.ok) return new Response('introuvable', { status: 404 });
      return new Response(r.body, {
        headers: {
          'Content-Type': 'text/csv; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'public, max-age=86400'
        }
      });
    }

    /* ============ Stockage non branche ============ */
    if (p.startsWith('/api/') && !env.DB) {
      return rep({ erreur: 'stockage non configure' }, 404);
    }

    /* ============ Connexion ============ */
    if (p === '/api/login' && request.method === 'POST') {
      const { login, mdp } = await request.json().catch(() => ({}));
      const u = await verifier(env, nettoyerLogin(login), String(mdp || ''));
      if (!u) {
        await new Promise(r => setTimeout(r, 400));      // ralentit les essais en masse
        return rep({ erreur: 'Identifiant ou mot de passe incorrect' }, 401);
      }
      const jeton = await creerJeton(env, u.login, u.role, u.nom);
      return new Response(JSON.stringify({ ok: true, login: u.login, role: u.role, nom: u.nom }), {
        headers: {
          ...JSONH,
          'Set-Cookie': 'ti_session=' + encodeURIComponent(jeton) +
            '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + (30 * 86400)
        }
      });
    }

    if (p === '/api/logout') {
      return new Response(JSON.stringify({ ok: true }), {
        headers: { ...JSONH, 'Set-Cookie': 'ti_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' }
      });
    }

    /* ============ Qui suis-je ============ */
    if (p === '/api/me') {
      const s = await session(request, env);
      if (!s) return rep({ erreur: 'non connecte' }, 401);
      return rep({ login: s.u, role: s.r, nom: s.n });
    }

    /* ============ Routes protegees ============ */
    if (p.startsWith('/api/')) {
      const s = await session(request, env);
      if (!s) return rep({ erreur: 'non connecte' }, 401);
      const admin = s.r === 'admin';

      /* ---- Dossiers ---- */
      if (p === '/api/data') {
        // Un agent ne lit QUE ses dossiers. Seule la direction peut viser
        // un autre compte, et uniquement en lecture.
        const vise = nettoyerLogin(url.searchParams.get('u') || '');
        const cible = (admin && vise) ? vise : s.u;

        if (request.method === 'GET') {
          const v = await env.DB.get('crm:' + cible);
          return new Response(v || 'null', { headers: JSONH });
        }

        if (request.method === 'PUT') {
          if (vise && vise !== s.u) return rep({ erreur: 'lecture seule sur ce compte' }, 403);
          let recu;
          try { recu = JSON.parse(await request.text()); }
          catch (e) { return rep({ erreur: 'JSON invalide' }, 400); }
          if (!recu || !Array.isArray(recu.projects)) return rep({ erreur: 'format inattendu' }, 400);

          // On n'ecrase JAMAIS des dossiers existants par une liste vide.
          if (recu.projects.length === 0 && !recu.force) {
            const ancien = await env.DB.get('crm:' + s.u);
            if (ancien) {
              try {
                const a = JSON.parse(ancien);
                if (a && Array.isArray(a.projects) && a.projects.length > 0) {
                  return rep({ erreur: 'refus : le cloud contient ' + a.projects.length + ' dossier(s), envoi vide ignore' }, 409);
                }
              } catch (e) { /* illisible : on laisse passer */ }
            }
          }
          recu.updated = recu.updated || Date.now();
          await env.DB.put('crm:' + s.u, JSON.stringify(recu));
          return rep({ ok: true, updated: recu.updated, dossiers: recu.projects.length });
        }
        return rep({ erreur: 'methode non autorisee' }, 405);
      }

      /* ---- Comptes (direction uniquement) ---- */
      if (p === '/api/users') {
        if (!admin) return rep({ erreur: 'reserve a la direction' }, 403);

        if (request.method === 'GET') {
          const liste = await env.DB.list({ prefix: 'user:' });
          const out = [];
          for (const k of liste.keys) {
            const c = JSON.parse(await env.DB.get(k.name) || '{}');
            const d = await env.DB.get('crm:' + k.name.slice(5));
            let n = 0;
            try { n = (JSON.parse(d || '{}').projects || []).length; } catch (e) { }
            out.push({ login: k.name.slice(5), nom: c.nom || '', role: c.role || 'agent', dossiers: n, cree: c.cree || 0 });
          }
          if (env.ADMIN_USER) out.unshift({ login: env.ADMIN_USER, nom: 'Direction', role: 'admin', dossiers: 0, fixe: true });
          return rep({ users: out });
        }

        if (request.method === 'POST') {
          const { login, mdp, nom } = await request.json().catch(() => ({}));
          const l = nettoyerLogin(login);
          if (!l || l.length < 3) return rep({ erreur: 'Identifiant trop court (3 caracteres minimum)' }, 400);
          if (String(mdp || '').length < 8) return rep({ erreur: 'Mot de passe trop court (8 caracteres minimum)' }, 400);
          if (env.ADMIN_USER && l === nettoyerLogin(env.ADMIN_USER)) return rep({ erreur: 'Identifiant reserve' }, 400);
          if (await lireCompte(env, l)) return rep({ erreur: 'Cet identifiant existe deja' }, 409);
          const sel = alea(16);
          await env.DB.put('user:' + l, JSON.stringify({
            nom: String(nom || l).slice(0, 60), role: 'agent',
            sel, hash: await empreinte(String(mdp), sel), cree: Date.now()
          }));
          return rep({ ok: true, login: l });
        }

        if (request.method === 'DELETE') {
          const l = nettoyerLogin(url.searchParams.get('login') || '');
          if (!l) return rep({ erreur: 'identifiant manquant' }, 400);
          if (!await lireCompte(env, l)) return rep({ erreur: 'compte introuvable' }, 404);
          await env.DB.delete('user:' + l);
          // Les dossiers de l'agent sont conserves : ils appartiennent a l'agence.
          return rep({ ok: true });
        }
        return rep({ erreur: 'methode non autorisee' }, 405);
      }

      /* ---- Changer un mot de passe ---- */
      if (p === '/api/password' && request.method === 'POST') {
        const { login, mdp } = await request.json().catch(() => ({}));
        const l = nettoyerLogin(login || s.u);
        if (!admin && l !== s.u) return rep({ erreur: 'reserve a la direction' }, 403);
        if (String(mdp || '').length < 8) return rep({ erreur: 'Mot de passe trop court (8 caracteres minimum)' }, 400);
        const c = await lireCompte(env, l);
        if (!c) return rep({ erreur: 'compte introuvable' }, 404);
        c.sel = alea(16);
        c.hash = await empreinte(String(mdp), c.sel);
        await env.DB.put('user:' + l, JSON.stringify(c));
        return rep({ ok: true });
      }

      return rep({ erreur: 'route inconnue' }, 404);
    }

    /* ============ Fichiers de l'application ============ */
    return env.ASSETS.fetch(request);
  }
};
