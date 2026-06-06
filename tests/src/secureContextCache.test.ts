import * as assert from 'assert';
import * as tls from 'tls';
import { createTlsPatch, resetCaches, LogLevel, ProxyAgentParams, SecureContextOptionsPatch } from '../../src/index';

// Any valid PEM certificate works as the injected additional CA; Node's bundled
// root certificates avoid a dependency on test fixture files.
const caCert = tls.rootCertificates[0];

function testParams(overrides: Partial<ProxyAgentParams> = {}): ProxyAgentParams {
	return {
		resolveProxy: async () => 'DIRECT',
		getProxyURL: () => undefined,
		getProxySupport: () => 'override',
		isAdditionalFetchSupportEnabled: () => true,
		isWebSocketPatchEnabled: () => false,
		addCertificatesV1: () => false,
		addCertificatesV2: () => true,
		isSecureContextCacheEnabled: () => true,
		loadSystemCertificatesFromNode: () => undefined,
		loadAdditionalCertificates: async () => [caCert],
		log: console,
		getLogLevel: () => LogLevel.Off,
		proxyResolveTelemetry: () => undefined,
		isUseHostProxyEnabled: () => false,
		env: {},
		...overrides,
	};
}

function connectionOptions(certs: (string | Buffer)[]): tls.ConnectionOptions {
	const options: tls.ConnectionOptions = {
		host: 'example.com',
		port: 443,
		servername: 'example.com',
	};
	(options as SecureContextOptionsPatch)._vscodeAdditionalCaCerts = certs;
	return options;
}

describe('SecureContext cache', function () {
	beforeEach(() => {
		resetCaches();
	});

	it('reuses the context for the same additional-CA set', function () {
		const { createSecureContext } = createTlsPatch(testParams(), tls);
		const certs = [caCert];

		const first = createSecureContext(connectionOptions(certs));
		const second = createSecureContext(connectionOptions(certs));
		assert.strictEqual(second, first);
	});

	it('builds a fresh context when the cache is disabled', function () {
		const { createSecureContext } = createTlsPatch(testParams({ isSecureContextCacheEnabled: () => false }), tls);
		const certs = [caCert];

		assert.notStrictEqual(createSecureContext(connectionOptions(certs)), createSecureContext(connectionOptions(certs)));
	});

	it('builds a fresh context for a different additional-CA array', function () {
		const { createSecureContext } = createTlsPatch(testParams(), tls);

		assert.notStrictEqual(createSecureContext(connectionOptions([caCert])), createSecureContext(connectionOptions([caCert])));
	});

	it('does not cache contexts without additional CA certificates', function () {
		const { createSecureContext } = createTlsPatch(testParams(), tls);

		assert.notStrictEqual(createSecureContext({}), createSecureContext({}));
	});

	it('reuses the context for the same caller-provided ca reference', function () {
		// This is the common hot path: proxy-agent's cached undici Agent passes its
		// `systemCA` array as `ca` on every connection, so the reference is stable.
		const { createSecureContext } = createTlsPatch(testParams(), tls);
		const ca = [caCert];

		const first = createSecureContext({ ca });
		const second = createSecureContext({ ca });
		assert.strictEqual(second, first);
	});

	it('builds a fresh context for a different caller-provided ca array', function () {
		const { createSecureContext } = createTlsPatch(testParams(), tls);

		assert.notStrictEqual(createSecureContext({ ca: [caCert] }), createSecureContext({ ca: [caCert] }));
	});

	it('keys the cache on context-affecting options', function () {
		const { createSecureContext } = createTlsPatch(testParams(), tls);
		const certs = [caCert];

		const tls12 = createSecureContext({ ...connectionOptions(certs), minVersion: 'TLSv1.2' });
		const tls13 = createSecureContext({ ...connectionOptions(certs), minVersion: 'TLSv1.3' });
		assert.notStrictEqual(tls13, tls12);
		assert.strictEqual(createSecureContext({ ...connectionOptions(certs), minVersion: 'TLSv1.2' }), tls12);
	});

	it('reports cacheable misses and hits, and skips uncacheable requests', function () {
		const results: boolean[] = [];
		const { createSecureContext } = createTlsPatch(testParams({ onSecureContextCacheResult: hit => results.push(hit) }), tls);
		const certs = [caCert];

		createSecureContext(connectionOptions(certs)); // Cacheable miss: builds and stores a fresh context.
		createSecureContext(connectionOptions(certs)); // Cacheable hit: same trust set reuses the context.
		createSecureContext({}); // Not cacheable: no trust material, so the callback must not fire.

		assert.deepStrictEqual(results, [false, true]);
	});

	it('drops cached contexts on resetCaches', function () {
		const { createSecureContext } = createTlsPatch(testParams(), tls);
		const certs = [caCert];

		const first = createSecureContext(connectionOptions(certs));
		resetCaches();
		assert.notStrictEqual(createSecureContext(connectionOptions(certs)), first);
	});
});
