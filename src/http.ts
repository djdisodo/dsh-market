/**
 * Minimal HTTP helpers shared by every market route: JSON serialization,
 * same-origin enforcement for mutating endpoints, and a size-capped JSON
 * body reader.
 */

import type { IncomingMessage, ServerResponse } from 'node:http'

/** Write a JSON payload with no-store caching. */
export function sendJson(response: ServerResponse, status: number, payload: unknown): void {
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
  })
  response.end(JSON.stringify(payload))
}

/**
 * True when the request's Origin, IF IT HAS ONE, matches its Host — required
 * on every POST route.
 *
 * An absent Origin is allowed (#648). The check exists to stop another web
 * page from driving this loopback API, and the Fetch spec has browsers send
 * `Origin` on every POST — including same-origin and cross-origin form
 * submissions. A request that arrives WITHOUT it therefore did not come from
 * a page at all, and a non-browser client can set any Origin it likes, so
 * refusing the header's absence bought nothing while breaking a whole
 * supported host: the Desktop app's own proxy strips `origin`, `host`,
 * `cookie` and `sec-fetch-site` before forwarding to the in-process host and
 * injects a cookie only that host can sign. Every mutating request from the
 * Desktop build was answered 403 `untrusted origin`.
 *
 * What still holds after the change, and is the part worth keeping:
 *
 * - a cross-site page is refused — its Origin is present and different;
 * - `Origin: null` (a sandboxed iframe, a `data:` document) is refused, because
 *   `null` is a present-but-unparseable origin, not an absent one;
 * - a same-host-but-different-port request is refused;
 * - an EMPTY Origin is refused too: the header being present and unparseable
 *   is not the same statement as its being absent, and only absence is what
 *   a stripping proxy produces.
 *
 * The header's absence is a statement about the client, not about intent, and
 * the intent is the only thing this can judge.
 *
 * @param request - the incoming request.
 * @returns whether the request may mutate market state.
 */
/**
 * Whether a `Host` header names an authority this deployment serves: the
 * loopback listener, or one it declared (#678).
 *
 * `Origin === Host` alone does not stop a DNS-rebinding page: the attacker
 * serves their page from `evil.com`, resolves that name to 127.0.0.1, and
 * the browser then connects to the loopback listener while sending
 * `Origin: http://evil.com` AND `Host: evil.com` — an equality that holds
 * for the attacker. `Host` is the one header the attack cannot forge, so it
 * is what has to name an authority HERE. Loopback alone is not enough either:
 * `dsh web --trusted-host <name>` exists so a GUI behind a reverse proxy, a
 * LAN name or a tunnel can be used at all, and that proxy forwards the
 * authority the browser typed — refusing it answered 403 `untrusted origin`
 * on the very page the market was serving.
 *
 * Declarations come from the deployment, never from the request: a rebinding
 * page can only offer its own name, which is in none of them. `declared` is
 * the host's own list (the complete one); this process's argv is the fallback
 * for a composition that publishes none, and is where `--trusted-host` is
 * written down.
 *
 * A declaration without a port matches that hostname on any port — the port a
 * proxy forwards is not the port the market listens on — while one carrying a
 * port matches exactly. `localhost` is included because browsers and RFC 6761
 * pin it to loopback; a subdomain like `localhost.evil.com` does not match.
 *
 * @param host - the request's `Host` header.
 * @param declared - authorities the host published, if it published any.
 * @returns whether it names an authority this deployment serves.
 */
export function hostAuthority(host: string | undefined, declared: readonly string[] = []): boolean {
  if (host === undefined) return false
  const lower = host.toLowerCase()
  // IPv6 literals keep their brackets; `[::1]:3080` → `[::1]`.
  const name = lower.startsWith('[') ? lower.slice(0, lower.indexOf(']') + 1) : lower.split(':')[0]!
  if (name === '127.0.0.1' || name === 'localhost' || name === '[::1]') return true
  return [...declared, ...argumentAuthorities()].some((entry) => {
    const value = entry.trim().toLowerCase()
    if (value === '') return false
    return value === lower || (!value.includes(':') && value === name)
  })
}

/** `--trusted-host <value>` and `--trusted-host=<value>` on this process's argv. */
function argumentAuthorities(): string[] {
  const values: string[] = []
  const argv = process.argv
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!
    if (argument === '--trusted-host') {
      const value = argv[index + 1]
      if (value !== undefined) values.push(value)
    } else if (argument.startsWith('--trusted-host=')) {
      values.push(argument.slice('--trusted-host='.length))
    }
  }
  return values
}

/**
 * The non-loopback authorities a host publishes on its `webRuntime` service
 * (`{ lanAddresses, trustedHosts }`), read structurally — a host that
 * publishes none, or publishes something malformed, contributes nothing.
 */
export function publishedAuthorities(source: unknown): readonly string[] {
  const list = (source as { trustedHosts?: unknown } | undefined)?.trustedHosts
  return Array.isArray(list) ? list.filter((entry): entry is string => typeof entry === 'string') : []
}

export function sameOrigin(request: IncomingMessage, declared: readonly string[] = []): boolean {
  // The rebinding defence (#678): a page on `evil.com` aimed at 127.0.0.1
  // sends a matching Origin/Host pair, so the equality below cannot see the
  // attack — Host is what it cannot forge.
  //
  // An ABSENT Host is a different statement. Every browser sends Host, so a
  // request without one did not come from a page at all — the same argument
  // the Origin rule above rests on — while a stripping proxy (the Desktop
  // build's, #648) may remove it and must not be refused for it. So the
  // authority is only checked when it is present, and a rebinding page can
  // never reach the branch that skips it.
  const host = request.headers.host
  if (host !== undefined && !hostAuthority(host, declared)) return false
  const origin = request.headers.origin
  // A missing Origin is not a cross-site request: browsers send it on every
  // POST, same-origin included, so its absence means the caller is not a
  // page — and a non-browser client can set any Origin it likes, so
  // refusing the absence bought nothing while breaking the Desktop proxy,
  // which strips it (#648).
  if (origin === undefined) return true
  try {
    return new URL(origin).host === host
  } catch {
    return false
  }
}

/** Read and parse a JSON request body, rejecting anything over 4 KiB. */
export async function readJsonBody(request: IncomingMessage, maxBytes = 4096): Promise<unknown> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    size += buffer.length
    if (size > maxBytes) throw new Error('request body too large')
    chunks.push(buffer)
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown
}
