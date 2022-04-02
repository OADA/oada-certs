/**
 * @license
 * Copyright 2022 Qlever LLC
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

/*
 Sign returns an encrypted JWT that represents the signed data.

 The result looks like this:
   dffji2ds.2f2309ijf234kf2l.2f823jhio
 that's just a random string, but in practice is a real JWT.

 "key" can either be an object with a "pem" key, or a jwk that can be converted to a pem.
 If the signing key has a kid (i.e. a "key id"), it will be added to the resulting JWT headers

 If there is no "options.header.jku" or no "options.header.kid", then we will put the public
 JWK into the JWT header directly.  If they are there, we will just put the jku and kid in there
 directly but not the public jwk.

*/

import { JWS, JWK as jose_JWK } from 'node-jose';
import cloneDeep from 'clone-deep';
import debug from 'debug';

import { InvalidKeyException, SignatureFailedException } from './errors';
import type { JOSEHeader, JWK } from './jwks-utils';

const trace = debug('oada-certs:trace');

export async function sign(
  payload: string | Record<string, unknown> | Buffer,
  key: string | JWK,
  {
    header: { typ = 'JWT', alg = 'RS256', ...header } = {},
  }: { header?: Partial<JOSEHeader> } = {}
) {
  if (!key)
    throw new InvalidKeyException(
      'You have to pass a valid JWK or an object with a pem key as the signing key'
    );
  // You can pass the pem in the key itself, or you can pass a JWK as the key:

  // AsKey needs the key to be just the pem string if it's a pem
  let privatejwk = await (typeof key === 'string'
    ? jose_JWK.asKey(key, 'pem')
    : key.kty === 'PEM'
    ? jose_JWK.asKey(key.pem, 'pem')
    : jose_JWK.asKey(key));
  // If (key.kid) privatejwk.kid = key.kid; // maintain kid from original if passed
  // options.header.kid can override the one in the private key:
  if (header?.kid) {
    trace(
      'sign: Setting kid in private key to options.header.kid value of ',
      header.kid
    );
    const json = privatejwk.toJSON(true) as JWK;
    json.kid = header.kid;
    privatejwk = await jose_JWK.asKey(json);
  }

  trace('sign: kid on privatejwk = ', privatejwk.kid);

  // Public only keeps kty, n, and e.  If kid is there, keep the key id too
  const publicjwk = privatejwk.toJSON() as JWK; // Without a parameter, this returns the public key
  if (privatejwk.kid) {
    publicjwk.kid = privatejwk.kid;
  }

  // If there is a kid on the key ("key id"), it will be kept in the JWT
  if (privatejwk.kid) {
    trace('key has a kid (', privatejwk.kid, '), putting in header');
    header.kid = privatejwk.kid;
  }

  // There is some wonkiness when the payload is just a regular string.  It seems
  // that the sign functions expect a string to be able to JSON.parse, so a simple
  // string variable breaks that.  We'll do a quick test and if it parses, we'll
  // use it.  If it doesn't, we'll JSON.stringify() it (which will surround it in quotes)
  if (typeof payload === 'string') {
    try {
      JSON.parse(payload);
    } catch {
      payload = JSON.stringify(payload);
    }
  }

  // The sign function will only sign strings, so if we have an object, we have to stringify it
  if (typeof payload === 'object') {
    payload = JSON.stringify(payload);
  }

  // We need to save the jwk in the header so that it can be validated even if the trusted list
  // is not available.  i.e. you should put
  // options.header.jku = "<URL to your key set>"
  // options.header.kid = "<id of this JWK in that key set>"
  // in options, and that will inform the trust check, but will will also include the JWK used
  // here in the header so that the JWT can be verified directly without performing the external trust check.
  // You should ALWAYS use the one at the jku URL when available rather than the one on the header.
  header.jwk = cloneDeep(publicjwk);

  try {
    return (await JWS.createSign(
      { format: 'compact' },
      {
        // @ts-expect-error The node-jose types are messed up...
        key: privatejwk,
        header: { typ, alg, ...header },
      }
    )
      .update(payload)
      .final()) as unknown as string;
  } catch (error: unknown) {
    trace(
      'Failed to sign payload, error was: ',
      error,
      ', payload = ',
      payload,
      ', key = ',
      key,
      ', options = ',
      {
        header: { typ, alg, ...header },
      }
    );
    throw new SignatureFailedException(
      'Unable to sign certificate with jose.JWS.createSign().update().final()',
      [error as Error]
    );
  }
}
