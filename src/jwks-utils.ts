/**
 * @license
 * Copyright 2014 Qlever LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import url from 'node:url';

import type { Entry } from 'type-fest';
import debug from 'debug';
import equal from 'deep-equal';
import jose from 'node-jose';
import request from 'superagent';

import type { RSA_JWK } from 'pem-jwk';

const trace = debug('oada-certs:jwks-utils:trace');
const info = debug('oada-certs:jwks-utils:info');
const warn = debug('oada-certs:jwks-utils:warn');

/**
 * @todo create union of JWK types discriminated on kty
 */
export interface JWK extends Partial<RSA_JWK & jose.JWK.RawKey> {
  /**
   * Must have "kty" to be a JWK
   */
  kty: string;
  pem?: string;
}
export interface JWKs {
  keys: readonly JWK[];
}

export interface JOSEHeader {
  alg: 'RS256';
  typ: string;
  kid?: string;
  jku?: string;
  jwk?: JWK;
}

/**
 * Cache jwks requests/responses:
 */
const jwksCache: Map<
  string,
  { jwks: JWKs; timePutIntoCache: number; strbytes: number }
> = new Map();
const cacheStaleTimeoutSec = 3600; // 1 hour
/**
 * How long to use cached value if network request fails
 */
const cacheFailureTimeout = 3600 * 24;
/**
 * Maximum MB allowed in the jwks cache before pruning old ones
 */
const cacheMaxSizeMB = 20;
function cacheSize() {
  return Array.from(jwksCache.keys()).reduce(
    (accumulator, uri) => accumulator + jwksCache.get(uri)!.strbytes,
    0
  );
}

export function cachePruneOldest() {
  let [olduri, oldest]: Entry<typeof jwksCache> = [
    '',
    {
      strbytes: 0,
      timePutIntoCache: Number.POSITIVE_INFINITY,
      jwks: { keys: [] },
    },
  ];
  for (const [uri, jwks] of jwksCache) {
    if (jwks.timePutIntoCache < oldest.timePutIntoCache) {
      [olduri, oldest] = [uri, jwks];
    }
  }

  return jwksCache.delete(olduri);
}

function putInCache(uri: string, jwks: JWKs, strbytes: number) {
  if (strbytes / 1_000_000 > cacheMaxSizeMB) {
    warn(
      'Refusing to cache jwks from uri %s because its size alone (%d) is larger than cacheMaxSizeMB (%d)',
      uri,
      strbytes,
      cacheMaxSizeMB
    );
    return false;
  }

  while (cacheSize() + strbytes > cacheMaxSizeMB) {
    if (!cachePruneOldest()) {
      break; // If pruneOldest fails, stop looping
    }
  }

  if (jwksCache.has(uri)) {
    trace(
      'Putting uri %s into cache with new timestamp, replacing previous entry',
      uri
    );
  }

  jwksCache.set(uri, {
    strbytes,
    timePutIntoCache: Date.now() / 1000,
    jwks,
  });
  return true;
}

const cachePruneIfFailureTimeout = (uri: string) => {
  const now = Date.now() / 1000;
  if (
    jwksCache.has(uri) &&
    now - jwksCache.get(uri)!.timePutIntoCache > cacheFailureTimeout
  ) {
    info(
      'jku request failed for uri %s, and it has been longer than cacheFailureTimeout, so removing that uri from cache due to failure',
      uri
    );
    // Remove from cache
    jwksCache.delete(uri);
  }
};

const cacheHasURIThatIsNotStale = (uri: string) => {
  const now = Date.now() / 1000;
  return (
    jwksCache.has(uri) &&
    now - jwksCache.get(uri)!.timePutIntoCache < cacheStaleTimeoutSec
  );
};

// -------------------------------------------------
// Primary exported module:

// Exporting some cache functions for testing:
export function clearJWKsCache() {
  jwksCache.clear();
}

export function getJWKsCache() {
  return jwksCache;
}

/**
 * Decide if an object is a JWK
 */
export function isJWK(key: unknown): key is JWK {
  return typeof key === 'object' && Boolean(key) && 'kty' in key!;
}

/**
 * Decide if an object is a set of JWKs
 */
export function isJWKset(set: unknown): set is JWKs {
  // @ts-expect-error stuff
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const keys = set?.keys;
  return Array.isArray(keys) && keys.some((element) => isJWK(element));
}

/**
 * Pick a JWK from a JWK set by its Key ID
 */
export function findJWK(kid: string | undefined, jwks: JWKs) {
  if (!kid) {
    return;
  }

  const result = jwks.keys.find((jwk) => isJWK(jwk) && jwk.kid === kid);
  trace(result, 'findJWK: returning ');
  return result;
}

async function fetchAndCacheJKU(
  uri: string,
  timeout: number
): Promise<JWKs | undefined> {
  const jwkRequest = request.get(uri);
  if (typeof jwkRequest.buffer === 'function') {
    void jwkRequest.buffer();
  }

  void jwkRequest.timeout(timeout);

  const resp = await jwkRequest.send();

  // If there was no error, then we can go ahead and try to parse the body (which could result in an error)
  trace(
    'Finished retrieving uri %s, had no error in the request, will now try to parse response.',
    uri
  );

  const jwks: unknown = JSON.parse(resp.text);
  if (!isJWKset(jwks)) {
    throw new Error(
      'jwks parsed successfully with JSON.parse, but it was not a valid jwks'
    );
  }

  // Put this successful jwks set into the cache
  if (putInCache(uri, jwks, resp.text.length)) {
    trace('Added jwks to cache for uri %s', uri);
    return jwks;
  }

  info('Failed to add jwks to cache for uri %', uri);
  return undefined;
}

export function decodeWithoutVerify(jwt: string) {
  const [sheader, spayload, signature] = jwt.split('.');
  trace('decodeWithoutVerify: parts before decoding = %s', [
    sheader,
    spayload,
    signature,
  ]);
  let header: JOSEHeader;
  let payload: unknown;
  try {
    header = JSON.parse(
      jose.util.base64url.decode(sheader!).toString()
    ) as JOSEHeader;
  } catch (error: unknown) {
    throw new Error(
      `Could not JSON.parse decoded header. Header string is: ${sheader}, error was: ${error}`
    );
  }

  try {
    payload = JSON.parse(jose.util.base64url.decode(spayload!).toString());
  } catch (error: unknown) {
    warn(
      'Could not JSON.parse payload, assuming it is a string to be left alone. Payload string is: %s, error was: %o',
      spayload,
      error
    );
    payload = spayload;
  }

  trace(
    'decodeWithoutVerify: decoded header = %o, payload = %o, signature = %s',
    header,
    payload,
    signature
  );
  return { header, payload, signature };
}

/**
 * Supported headers: [kid, jwk, jku]
 */
export async function jwkForSignature(
  sig: string,
  hint: false | string | JWKs | JWK,
  { timeout = 1000 }: { timeout?: number } = {}
) {
  const { header } = decodeWithoutVerify(sig);

  const checkJWKEqualsJoseJWK = (jwk?: JWK) => {
    trace(jwk, 'checkJWKEqualsJoseJWK: started function');
    if (!jwk) {
      warn(
        'jwk is falsey: there was no final JWK to check against the JOSE header.  Did you use a jku on an untrusted signature?'
      );
      throw new Error(
        'There was no final JWK to check against the JOSE header.  Did you use a jku on an untrusted signature?'
      );
    }

    if (header.jwk && !equal(jwk, header.jwk, { strict: true })) {
      warn('header.jwk (%o) did not match jwk (%o)', header.jwk, jwk);
      throw new Error('JWK did not match jwk JOSE header');
    }

    trace(jwk, 'checkJWKEqualsJoseJWK: successful');
    return jwk;
  };

  // Retrieve JWKS from a JKU URI
  // Update for 1.0.6: Adding an in-memory cache that will both
  //   1: speedup requests with jku's, and
  //   2: keep working with cached copy for 24 hours in the event of network outage.
  // The cache will respond immediately with a cached value if the cached value is less than
  // 1 hour old and the kid is in it.  It will always go get the latest jwks at the URL to
  // update the cache, but if the kid is already in the cached copy it will return that immediately
  // and not wait on the request to finish.  If the kid is not found in the cached value, it will
  // wait for the request to finish and then look for the kid in the new copy.  In this way, if a
  // new kid is published in your jwks, it will be immediately available to all clients.  If a key
  // is deemed no longer trusted and removed from the jwks, then it will only validate at most one
  // time in at most a 1 hour window after un-publishing.
  async function getJWK(uri: string): Promise<JWK> {
    // MUST use HTTPS (not HTTP)
    const u = new URL(uri);
    u.protocol = 'https';
    uri = url.format(u);

    const resp = fetchAndCacheJKU(uri, timeout);

    // Fire off the request here first, then immediately check cache before javascript event queue moves on.
    // If it's there, then that "thread" of execution will call the callback instead of the one after
    // the request finishes.  If it wasn't there, then the request's callback here will call it.
    trace(
      'Sending out GET request for uri %s, will check cache while it is waiting',
      uri
    );
    let jwks: JWKs;
    try {
      // Now, check if we already have the uri in the cache and
      // if the kid is already in it's list of keys:
      trace('Checking cache for non-stale uri ', uri);
      if (cacheHasURIThatIsNotStale(uri)) {
        trace(
          'Found uri %s in cache and it is not stale, returning it immediately',
          uri
        );
        const jwk = findJWK(header.kid, jwksCache.get(uri)!.jwks);
        if (jwk) {
          return checkJWKEqualsJoseJWK(jwk);
        }
      }

      // If we get here, then we did not have a valid, un-stale kid in the cache, so we need
      // to wait on the request to call the callback instead (above).  If it fails above, then it
      // will continue to use the stale URI until the 24-hour failure period.  The callback for the
      // overall function will end up being called in the callback for the request.
      trace(
        'Did not find non-stale uri %s in cache, waiting on request to complete instead',
        uri
      );
      const result = await resp;
      if (!result) {
        throw new Error(
          `Failed to get jwks from uri ${uri}, and it was not in the cache`
        );
      }

      jwks = result;
    } catch (error: unknown) {
      // If we get to this point, either jwks is valid and in the jwks variable, or we had an error
      warn('jku request failed for uri %s', uri);
      // If the request had an error (i.e. network or host is down now), let's check if we have
      // the jwks in the cache.  If we do, we'll go ahead and use it for up to 24 hours before
      // removing it due to the failure.
      cachePruneIfFailureTimeout(uri);
      // Now if it's not in the cache, since the request had an error, then return the error
      if (!jwksCache.has(uri)) {
        warn('uri (%s) had error, and it is not in cache, throwing', uri);
        throw error;
      }

      // If we get here, there was an error, but it was in the cache still before the cacheFailureTimeout,
      // so put that in the main jwks variable to check later
      info(
        'jku request failed for uri %s, but we have cached copy that we will use for 24 hours',
        uri
      );
      jwks = jwksCache.get(uri)!.jwks;
    }

    // And finally, if we got to this point, we either did not have an error, or we had an error but
    // we decided to use our cached value.  Either way, the jwks variable now has a valid jwks in it.
    // This ends the thread that runs after the web request finishes.
    trace(
      'Finished with request path, looking for header.kid (%s) in retrieved jwks:%o',
      header.kid,
      jwks
    );
    return checkJWKEqualsJoseJWK(findJWK(header.kid, jwks));
  }

  // Now we can do the main part of the function which checks the hint and then calls one of
  // the functions above....
  // This hint thing is complicated....
  // It was designed to make it simple to say something like:
  // "hint: I looked up the JKU ot JWK on the signature, and it was from a trusted source."
  // (i.e. hint = truthy),
  // and it's truthy value is then either the JWKS (object) from the trusted source,
  //     or the jku (string) of the trusted source's jwks
  // or
  // "hint: I looked at my trusted sources and this one doesn't have a jwk or jku that matches."
  // (i.e. hint === false)
  // which means "just use the header on the signature because I have no outside reference that verifies it"
  //
  // - If boolean false, use the jku from the jose header and if no jku then use jose's jwk
  // - If boolean true, throw error (it should have been either an object or a string)
  // - If string, assume string is a jku uri, go get that URI and then check jose's jwk against it
  // - If object and looks like a jwks, look for jose's jwk in the set
  // - If object and looks like a jwk, compare that jwk with jose's jwk
  switch (typeof hint) {
    case 'boolean':
      if (!hint) {
        // Lookup solely based on JOSE headers
        if (header.jku) {
          warn(
            'signature has a jku key, but it is untrusted and therefore ignored to avoid getting potentially malicious URIs.'
          );
        }

        if (!header.jwk) {
          warn('signature is untrusted and has no jwk key to check');
          return checkJWKEqualsJoseJWK();
        }

        trace(
          'hint is boolean false, but we do have a jwk in the header so we will check that.'
        );
        // If no jku uri, then just use the jwk on the jose header as last resort
        return checkJWKEqualsJoseJWK(header.jwk);
      }

      break;
    case 'string':
      trace('hint is a string, assuming URL to getJWK');
      return getJWK(hint);
    case 'object':
      if (isJWKset(hint)) {
        trace('hint is object, looks like jwk set, checking that');
        return checkJWKEqualsJoseJWK(findJWK(header.kid, hint));
      }

      if (isJWK(hint) && header.kid === hint.kid) {
        trace('hint is object, looks like jwk w/ same kid, checking');
        return checkJWKEqualsJoseJWK(hint);
      }

      break;

    default:
  }

  // If we get here, the hint didn't make sense so we error out:
  warn('jwkForSignature: Hint was invalid!');
  throw new Error('Invalid hint');
}
