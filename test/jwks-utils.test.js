/**
 * @license
 * Copyright 2014 Open Ag Data Alliance
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
chai.use(chaiAsPromised);
const { expect } = chai;
const request = require('superagent');
const jose = require('node-jose');

const jwkUtil = require('../dist/jwks-utils.js');

const jwkSet = require('./jwk_set.json');
const jwkSetPriv = require('./jwk_set_priv.json');
const jwk = jwkSet.keys[0];
const jwk2 = jwkSet.keys[1];
let key = false;

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

describe('jwks-utils', () => {
  before(async () => {
    // Setup a couple of keys and a keystore to use:
    key = await jose.JWK.asKey(jwkSetPriv.keys[0]);
  });

  // -----------------------------------------------------------
  describe('#isJWK', () => {
    it('should return true for a JWK', () => {
      expect(jwkUtil.isJWK(jwk)).to.equal(true);
    });

    it('should return false for object without "kty"', () => {
      expect(jwkUtil.isJWK({ foo: 'bar' })).to.equal(false);
    });
  });

  // -----------------------------------------------------------
  describe('#isJWKset', () => {
    it('should return true for a JWK Set', () => {
      expect(jwkUtil.isJWKset(jwkSet)).to.equal(true);
    });

    it('should return false for object without "kty"', () => {
      expect(jwkUtil.isJWKset({ foo: 'bar' })).to.equal(false);
    });
  });

  // -----------------------------------------------------------
  describe('#findJWK', () => {
    it('should find JWK with matching "kid"', () => {
      const { kid } = jwk;
      expect(jwkUtil.findJWK(kid, jwkSet)).to.deep.equal(jwk);
    });

    it('shouldn\'t find a JWK for not matching "kid"', () => {
      expect(jwkUtil.findJWK('non-existent', jwkSet)).to.equal(undefined);
    });

    it('should not find a JWK for undefined "kid"', () => {
      expect(jwkUtil.findJWK(undefined, jwkSet)).to.be.not.ok;
    });
  });

  // -----------------------------------------------------------
  describe('#jwkForSignature', () => {
    const options_ = { format: 'compact' };
    it('should work with "jwk" JOSE header', async () => {
      const sig = await jose.JWS.createSign(options_, { key, header: { jwk } })
        .update('FOO BAR')
        .final();

      return expect(
        jwkUtil.jwkForSignature(sig, false)
      ).to.eventually.deep.equal(jwk);
    });

    it('should NOT work with "jku" JOSE header if hint is false (untrusted)', async () => {
      const sig = await jose.JWS.createSign(options_, {
        key,
        header: {
          jku: 'https://localhost:3000/jwks_uri',
          kid: jwk.kid,
        },
      })
        .update('FOO BAR')
        .final();

      return expect(jwkUtil.jwkForSignature(sig, false)).to.eventually.be
        .rejected;
    });

    it('should work with "jku" JOSE header if hint is a string and is the same as the jku header', async () => {
      const sig = await jose.JWS.createSign(options_, {
        key,
        header: {
          jku: 'https://localhost:3000/jwks_uri',
          kid: jwk.kid,
        },
      })
        .update('FOO BAR')
        .final();

      return expect(
        jwkUtil.jwkForSignature(sig, 'https://localhost:3000/jwks_uri')
      ).to.eventually.deep.equal(jwk);
    });

    it('should by default use the hint string to fetch the jwks instead of the jku on the header if they do not match', async () => {
      const sig = await jose.JWS.createSign(options_, {
        key,
        header: {
          jku: 'https://localhost:3000/does_not_exist',
          kid: jwk.kid,
        },
      })
        .update('FOO BAR')
        .final();

      return expect(
        jwkUtil.jwkForSignature(sig, 'https://localhost:3000/jwks_uri')
      ).to.eventually.deep.equal(jwk);
    });

    it('should work with URI hint', async () => {
      const sig = await jose.JWS.createSign(options_, {
        key,
        header: {
          kid: jwk.kid,
        },
      })
        .update('FOO BAR')
        .final();

      return expect(
        jwkUtil.jwkForSignature(sig, 'https://localhost:3000/jwks_uri')
      ).to.eventually.deep.equal(jwk);
    });

    it('should work with jwk hint', async () => {
      const sig = await jose.JWS.createSign(options_, {
        key,
        header: {
          kid: jwk.kid,
        },
      })
        .update('FOO BAR')
        .final();

      return expect(jwkUtil.jwkForSignature(sig, jwk)).to.eventually.deep.equal(
        jwk
      );
    });

    it('should work with jwks hint', async () => {
      const sig = await jose.JWS.createSign(options_, {
        key,
        header: {
          kid: jwk.kid,
        },
      })
        .update('FOO BAR')
        .final();

      return expect(
        jwkUtil.jwkForSignature(sig, jwkSet)
      ).to.eventually.deep.equal(jwk);
    });

    it('should fail for invalid jwk/jwks hint', async () => {
      const sig = await jose.JWS.createSign(options_, {
        key,
        header: {
          kid: jwk.kid,
        },
      })
        .update('FOO BAR')
        .final();

      return expect(jwkUtil.jwkForSignature(sig, {})).to.eventually.be.rejected;
    });

    it('should fail for invalid hints', async () => {
      const sig = await jose.JWS.createSign(options_, { key })
        .update('FOO BAR')
        .final();

      return expect(jwkUtil.jwkForSignature(sig, true)).to.eventually.be
        .rejected;
    });

    it('should fail when JWKS URI can not be parsed', async () => {
      const sig = await jose.JWS.createSign(options_, { key })
        .update('FOO BAR')
        .final();

      return expect(
        jwkUtil.jwkForSignature(sig, 'https://localhost:3000/jwks_uri_broken')
      ).to.eventually.be.rejected;
    });

    it('should fail when JWKS URI hosts an invalid JWK', async () => {
      const sig = await jose.JWS.createSign(options_, { key })
        .update('FOO BAR')
        .final();

      return expect(
        jwkUtil.jwkForSignature(sig, 'https://localhost:3000/jwks_uri_invalid')
      ).to.eventually.be.rejected;
    });

    it('should timeout', async () => {
      const sig = await jose.JWS.createSign(options_, {
        key,
        header: { kid: jwk.kid },
      })
        .update('FOO BAR')
        .final();

      const options = { timeout: 1 };

      return expect(
        jwkUtil.jwkForSignature(
          sig,
          'https://localhost:3000/jwks_uri_slow',
          options
        )
      ).to.eventually.be.rejected;
    });

    describe('with both "jku" and "jwk" JOSE headers', () => {
      it('should work when they agree', async () => {
        const sig = await jose.JWS.createSign(options_, {
          key,
          header: {
            jku: 'https://localhost:3000/jwks_uri',
            kid: jwk.kid,
            jwk,
          },
        })
          .update('FOO BAR')
          .final();

        return expect(
          jwkUtil.jwkForSignature(sig, 'https://localhost:3000/jwks_uri')
        ).to.eventually.deep.equal(jwk);
      });

      it('should error when they disagree', async () => {
        const sig = await jose.JWS.createSign(options_, {
          key,
          header: {
            jku: 'https://localhost:3000/jwks_uri',
            kid: jwk.kid,
            jwk: jwk2,
          },
        })
          .update('FOO BAR')
          .final();

        return expect(
          jwkUtil.jwkForSignature(sig, 'https://localhost:3000/jwks_uri')
        ).to.eventually.be.rejected;
      });
    });

    it('should work with jku from cache when jku fails after first get', async () => {
      const jkuThatDies =
        'https://localhost:3000/jwks_uri_dies_after_first_request';
      const resurrectJku =
        'https://localhost:3000/reset_jwks_uri_dies_after_first_request';

      await request.get(resurrectJku);
      const sig = await jose.JWS.createSign(options_, {
        key,
        header: {
          jku: jkuThatDies,
          kid: jwk.kid,
        },
      })
        .update('FOO BAR')
        .final();

      return jwkUtil
        .jwkForSignature(sig, jkuThatDies)
        .then((key) => {
          // First request should be fine
          expect(key).to.deep.equal(jwk);

          return jwkUtil.jwkForSignature(sig, jkuThatDies);
        })
        .then((key) => expect(key).to.deep.equal(jwk));
    });
  });
});
