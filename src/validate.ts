/**
 * @license
 * Copyright 2019 Open Ag Data Alliance
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

import debug from 'debug';
import jose from 'node-jose';
import request from 'superagent';

import {
  JWK,
  JWKs,
  clearJWKsCache,
  decodeWithoutVerify,
  findJWK,
  isJWKset,
  jwkForSignature,
} from './jwks-utils.js';
import type { JOSEHeader } from './jwks-utils';

const warn = debug('oada-certs#validate:warn');
const info = debug('oada-certs#validate:info');
const trace = debug('oada-certs#validate:trace');

export const TRUSTED_LIST_URI =
  'https://oada.github.io/oada-trusted-lists/client-registration-v2.json';

export interface ValidateResult {
  /**
   * Valid and JWK/JKU+KID is in trusted list
   */
  trusted: boolean;
  /**
   * Whether signature is a valid signature, regardless of trusted list status
   */
  valid: boolean;
  /**
   * The actual decoded client certificate
   */
  payload?: unknown;
  header?: JOSEHeader;
  /**
   * Array of objects with "message" keys giving details on the validation results
   */
  details: ReadonlyArray<{ message: string }>;
}

export interface ValidateOptions {
  /**
   * Timeout in ms
   * @default 1000
   */
  timeout: number;
  /**
   * Timeout in seconds
   * @default 3600
   */
  trustedListCacheTime: number;
  additionalTrustedListURIs: readonly string[];
  /**
   * @default false
   */
  disableDefaultTrustedListURI: boolean;
}

export type TrustedList =
  | readonly string[]
  | { version: '2'; jkus?: unknown; jwks?: unknown };
const trustedListCache: Map<
  string,
  { timeLastFetched: number; body: TrustedList }
> = new Map();
export function clearCache() {
  trustedListCache.clear(); // Clear our cache of trusted lists
  clearJWKsCache(); // And clear the jwku library's cache of jwks sets
} // Mainly useful for testing...

// TS is dumb about Array.isArray
function isArray(value: unknown): value is unknown[] | readonly unknown[] {
  return Array.isArray(value);
}

type Lists = ReturnType<typeof getLists> extends Promise<infer L> ? L : never;
async function getLists(
  trustedListURIs: readonly string[],
  {
    trustedListCacheTime,
    timeout,
  }: { trustedListCacheTime: number; timeout: number }
) {
  const now = Date.now() / 1000; // Convert ms to sec
  return Promise.all(
    trustedListURIs.map(async (listURI) => {
      if (
        !trustedListCache.has(listURI) ||
        trustedListCache.get(listURI)!.timeLastFetched <
          now - trustedListCacheTime
      ) {
        // Either not cached, or cache is old
        trace('listURI %s is not in cache or is stale, fetching...', listURI);
        try {
          const { body } = (await request.get(listURI).timeout(timeout)) as {
            body: TrustedList;
          };
          const newCacheObject = {
            timeLastFetched: now,
            body,
          };
          trustedListCache.set(listURI, newCacheObject);
          trace(
            'Fetched list from URI %s, putting this into the cache: %o',
            listURI,
            newCacheObject
          );
          return { listURI, ...newCacheObject };
        } catch {
          warn('Unable to fetch trusted list at URI %s', listURI);
          return;
        }
      }

      // Else, we have it in the cache, so return the cached body directly
      const cached = trustedListCache.get(listURI)!;
      trace(
        'listURI %s is in cache, returning cached value: %o',
        listURI,
        cached
      );
      return { listURI, ...cached };
    })
  );
}

/**
 * Look in the list for a jku or jwk that matches the one on this signature:
 */
function findList(
  lists: Readonly<Lists>,
  { header }: ReturnType<typeof decodeWithoutVerify>
): string | JWKs | undefined {
  for (const list of lists) {
    if (!list?.body) {
      continue;
    }

    const { body, listURI } = list;
    // V1 trusted list: an array of strings that are all jku's (no jwk's supported in trusted list)
    if (isArray(body)) {
      const found = body.find((jku) => jku === header.jku); // Returns jku string
      if (found) {
        return found;
      }

      continue;
    }

    // V2 trusted list: an object with a list of jku's and/or jwk's
    if (body.version === '2') {
      // Check jku list to see if we have a match in this header:
      const foundJKU = isArray(body.jkus)
        ? // If jkus is a list of strings of trusted URL's, see if it matches jku in header:
          (body.jkus.find(
            (jku) =>
              typeof jku === 'string' && jku.length > 0 && jku === header.jku
          ) as string)
        : undefined;

      // Check jwks key set in trusted list if there is one
      const foundJWKInJWKS =
        isJWKset(body.jwks) &&
        // Search through the trusted JWKS set
        header.jwk?.kid &&
        findJWK(header.jwk.kid, body.jwks)
          ? body.jwks // Keep the JWKS to use later in checking signature
          : undefined;

      trace(
        'Searched list %s for jwk or jku from header, foundJKU = %s, foundJWKInJWKS = %s',
        listURI,
        foundJKU,
        foundJWKInJWKS
      );
      // Returns either a JKU string, or a JWKS object
      const result = foundJKU ?? foundJWKInJWKS;
      if (result) {
        return result;
      }
    }
  }

  return undefined;
}

export async function validate(
  sig: string,
  {
    timeout = 1000,
    trustedListCacheTime = 3600,
    additionalTrustedListURIs = [],
    disableDefaultTrustedListURI = false,
  }: Partial<ValidateOptions> = {}
): Promise<ValidateResult> {
  const details: Array<{ message: string }> = [];
  try {
    // Build the list of all the trusted lists we're going to check
    const trustedListURIs = (
      disableDefaultTrustedListURI ? [] : [TRUSTED_LIST_URI]
    ).concat(additionalTrustedListURIs);
    trace('additionalTrustedListURIs = %s', additionalTrustedListURIs);
    trace('Using trustedListURIs = %s', trustedListURIs);

    // ---------------------------------------------------------------------------
    // Loop over all the trusted list URI's, checking if we already have in cache
    // If in cache, also check that they are not stale and need to be replaced
    trace(trustedListCache, 'Starting trusted lists cache check');
    const lists = await getLists(trustedListURIs, {
      trustedListCacheTime,
      timeout,
    });

    // -----------------------------------------------------------------------------
    // Now, look through all the lists to see if the jku on the signature is in
    // any of the trusted lists
    trace('List caching section finished, lists = %s', lists);
    // Jwku.decodeWithoutVerify throws if the signature is invalid
    let decoded: ReturnType<typeof decodeWithoutVerify>;
    try {
      decoded = decodeWithoutVerify(sig);
    } catch (error: unknown) {
      details.push({
        message: `Could not decode signature with jwku.decodeWithoutVerify: ${JSON.stringify(
          error,
          null,
          '  '
        )}`,
      });
      throw new Error('Decoding failed for signature');
    }

    if (!decoded?.header) {
      trace(decoded, 'Decoded signature has no header');
      details.push({ message: 'Decoding failed for certificate' });
      throw new Error('Decoding failed for signature');
    }

    trace('Tried decoding the signature, resulting in decoded = %o', decoded);

    // Now look in the list for a jku or jwk that matches the one on this signature:
    const foundList = findList(lists, decoded);
    if (!foundList) {
      info(
        'header of decoded signature does not have a jku or jwk key that ' +
          'exists in any of the trusted lists. decoded.header = ',
        decoded.header
      );
      details.push({
        message: `Did not find trusted list corresponding to this decoded signature header: ${JSON.stringify(
          decoded.header
        )}`,
      });
    }

    // FoundList is now either a string (jku) or object (trusted jwks)
    trace(
      'Result of search for jku or jwk that matches a trusted list entry = ',
      foundList
    );
    details.push({
      message: `Matched decoded header to trusted list: ${JSON.stringify(
        foundList,
        null,
        '  '
      )}`,
    });

    // IMPORTANT: !!foundList at this point does not know if the signature
    // actually is valid and trusted, it only knows that the signature pointed
    // at something in a trusted list. We don't really know if it is trusted
    // until we check both that the signature pointed at something in a trusted
    // list, AND the signature was signed with the private key of the trusted
    // thing it pointed at. Therefore, in the next .then() block when we call
    // verify with the jwk from here, if it throws then we know the signature
    // couldn't be verified and will therefore be considered untrusted
    let trusted = Boolean(foundList);
    // If we found the jku from the header in a trusted list, then the call
    // below will tell jwkForSignature to use that jku, go there and get the
    // list of keys, then use the kid to lookup the jwk. If it was not found in
    // a trusted list, then jwkForSignature will just return either the jwk
    // from the header directly or the corresponding jwk from a jku lookup
    let jwk: JWK | undefined;
    try {
      jwk = await jwkForSignature(sig, foundList ? foundList : false, {
        timeout,
      });
    } catch (error: unknown) {
      details.push({
        message: `Failed to figure out public key (JWK) for signature. Error from jwkForSignature was:${JSON.stringify(
          error
        )}`,
      });
    }

    if (!decoded) {
      details.push({ message: 'Decoding failed for certificate' });
      return {
        trusted: false,
        valid: false,
        details,
      };
    }

    // Now we can go ahead and verify the signature with the jwk:
    let valid = false;
    try {
      valid = Boolean(
        jwk &&
          (await jose.JWS.createVerify(await jose.JWK.asKey(jwk)).verify(sig))
      ); // Actually returns an object with header, payload, protected, key
    } catch (error: unknown) {
      details.push({
        message: `Failed to verify JWT signature with public key. jwt.verify said: ${JSON.stringify(
          error,
          null,
          '  '
        )}`,
      });
    }

    if (!valid) {
      details.push({
        message:
          'jwt.verify says it does not verify with the given JWK. Setting valid = false, trusted = false.',
      });
      trusted = false;
    }

    // Made it all the way to the end! Return the results:
    return {
      trusted,
      details,
      valid,
      ...decoded,
    };
  } catch (error: unknown) {
    info(error, 'Error in oadacerts.validate');
    details.push({
      message: `Error in oadacerts.validate. err was: ${JSON.stringify(
        error,
        null,
        '  '
      )}`,
    });
    return {
      trusted: false,
      valid: false,
      details,
    };
  }
}
