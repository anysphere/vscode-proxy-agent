import * as tls from 'tls';

type SecureContext = ReturnType<typeof tls.createSecureContext>;

// Cache of SecureContexts built by the patched createSecureContext for a given trust set.
// OpenSSL 3's provider-based decoder makes parsing a CA set expensive, and that cost is otherwise
// paid on every TLS connection because a fresh context is built each time. Reusing one context per
// distinct trust set is the mitigation OpenSSL itself recommends ("load once, use multiple times",
// https://github.com/openssl/openssl/discussions/22900).
//
// The trust set is whichever of the caller `ca` and the injected additional-CA array are present —
// both are stable references in practice: `ca` is proxy-agent's `systemCA` carried by a cached
// undici Agent, and the additional-CA array comes from getOrLoadAdditionalCertificates, which caches
// and reuses it. The context is keyed on those two references, then on a signature of the few other
// context-affecting options the cache is willing to key on. Anything else (per-identity key material,
// a string `ca` that can't be referenced, crl/dhparam/...) disqualifies caching, so those callers get
// a fresh context exactly as before. The WeakMaps let contexts for a dropped array be collected.
//
// Cached contexts are shared across connections and must never be mutated after they have been stored.
const absentCerts = {}; // sentinel WeakMap key standing in for an absent ca / additional-CA array
let cache = new WeakMap<object, WeakMap<object, Map<string, SecureContext>>>();

/**
 * Context-affecting options the cache keys on. They are scalar options a client might reasonably
 * set, so differing values simply produce distinct cache entries.
 */
const keyedContextOptions = ['secureProtocol', 'minVersion', 'maxVersion', 'ciphers', 'sigalgs', 'ecdhCurve', 'secureOptions', 'honorCipherOrder'] as const;

/**
 * Options whose presence disqualifies caching. Per-identity key material is unsafe to share across
 * connections; the rest (crl, dhparam, ...) are rare enough that building a fresh context — the same
 * cost as without the cache — is the simpler, safer choice. The trust roots (`ca` and the injected
 * additional-CA set) are deliberately NOT here: they are the trust material the cache keys on.
 */
const disqualifyingContextOptions = ['cert', 'key', 'pfx', 'passphrase', 'clientCertEngine', 'privateKeyEngine', 'privateKeyIdentifier', 'ticketKeys', 'crl', 'dhparam', 'sessionIdContext', 'sessionTimeout', 'allowPartialTrustChain'] as const;

interface CacheKey {
	caKey: object;
	additionalKey: object;
	signature: string;
}

/**
 * Computes the cache key for the given options, or undefined when they are not cacheable. Per-socket
 * options (servername, session, ALPNProtocols, rejectUnauthorized, ...) do not affect the
 * SecureContext and are deliberately ignored so they cannot split the cache.
 */
function cacheKey(details: tls.SecureContextOptions): CacheKey | undefined {
	const options = details as Record<string, unknown>;

	for (const option of disqualifyingContextOptions) {
		if (options[option] !== undefined) {
			return undefined;
		}
	}

	const ca = options['ca'];
	const additional = options['_vscodeAdditionalCaCerts'];

	// WeakMap keys must be objects, so a string `ca` (single PEM) can't be keyed on. Arrays and
	// Buffers are objects. Without any trust material there is nothing expensive to cache.
	if (ca !== undefined && typeof ca !== 'object') {
		return undefined;
	}
	if (additional !== undefined && typeof additional !== 'object') {
		return undefined;
	}
	if (ca === undefined && additional === undefined) {
		return undefined;
	}

	const parts: string[] = [];
	for (const option of keyedContextOptions) {
		const value = options[option];
		if (value !== undefined && typeof value === 'object') {
			return undefined;
		}
		parts.push(value === undefined ? '' : String(value));
	}

	return {
		caKey: (ca as object | undefined) ?? absentCerts,
		additionalKey: (additional as object | undefined) ?? absentCerts,
		signature: parts.join('|'),
	};
}

/**
 * Returns the cached SecureContext for the given options, or undefined when there is no cached entry
 * or the options are not cacheable.
 */
export function getCachedSecureContext(details: tls.SecureContextOptions): SecureContext | undefined {
	const key = cacheKey(details);
	if (key === undefined) {
		return undefined;
	}
	return cache.get(key.caKey)?.get(key.additionalKey)?.get(key.signature);
}

/**
 * Stores a SecureContext built for the given options. No-op when the options are not cacheable. The
 * context is shared with every later cache hit, so it must not be mutated after being stored.
 */
export function cacheSecureContext(details: tls.SecureContextOptions, context: SecureContext): void {
	const key = cacheKey(details);
	if (key === undefined) {
		return;
	}

	let byAdditional = cache.get(key.caKey);
	if (!byAdditional) {
		byAdditional = new WeakMap();
		cache.set(key.caKey, byAdditional);
	}
	let bySignature = byAdditional.get(key.additionalKey);
	if (!bySignature) {
		bySignature = new Map();
		byAdditional.set(key.additionalKey, bySignature);
	}
	bySignature.set(key.signature, context);
}

/**
 * Drops all cached SecureContexts. Called from resetCaches() so contexts built for a previous
 * certificate set cannot outlive it.
 */
export function clearSecureContextCache(): void {
	cache = new WeakMap();
}
