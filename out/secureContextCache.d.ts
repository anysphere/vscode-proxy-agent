/// <reference types="node" />
import * as tls from 'tls';
type SecureContext = ReturnType<typeof tls.createSecureContext>;
export interface SecureContextCacheKey {
    caKey: object;
    additionalKey: object;
    signature: string;
}
/**
 * Computes the cache key for the given options, or undefined when they are not cacheable. Per-socket
 * options (servername, session, ALPNProtocols, rejectUnauthorized, ...) do not affect the
 * SecureContext and are deliberately ignored so they cannot split the cache.
 *
 * Callers compute this once and pass it to the lookup and store below, so the option scan is not
 * repeated; a defined result also means the request is cacheable.
 */
export declare function secureContextCacheKey(details: tls.SecureContextOptions): SecureContextCacheKey | undefined;
/**
 * Returns the cached SecureContext for the given key, or undefined when nothing is stored for it yet.
 */
export declare function getCachedSecureContext(key: SecureContextCacheKey): SecureContext | undefined;
/**
 * Stores a SecureContext under the given key. The context is shared with every later cache hit, so it
 * must not be mutated after being stored.
 */
export declare function cacheSecureContext(key: SecureContextCacheKey, context: SecureContext): void;
/**
 * Drops all cached SecureContexts. Called from resetCaches() so contexts built for a previous
 * certificate set cannot outlive it.
 */
export declare function clearSecureContextCache(): void;
export {};
