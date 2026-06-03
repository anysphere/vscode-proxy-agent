/// <reference types="node" />
import * as tls from 'tls';
type SecureContext = ReturnType<typeof tls.createSecureContext>;
/**
 * Returns the cached SecureContext for the given options, or undefined when there is no cached entry
 * or the options are not cacheable.
 */
export declare function getCachedSecureContext(details: tls.SecureContextOptions): SecureContext | undefined;
/**
 * Stores a SecureContext built for the given options. No-op when the options are not cacheable. The
 * context is shared with every later cache hit, so it must not be mutated after being stored.
 */
export declare function cacheSecureContext(details: tls.SecureContextOptions, context: SecureContext): void;
/**
 * Drops all cached SecureContexts. Called from resetCaches() so contexts built for a previous
 * certificate set cannot outlive it.
 */
export declare function clearSecureContextCache(): void;
export {};
