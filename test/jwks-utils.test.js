/* Copyright 2014 Open Ag Data Alliance
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

'use strict';

const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
chai.use(chaiAsPromised);
const Promise = require('bluebird');
const expect = chai.expect;
const request = require('superagent');
const jose = require('node-jose');

const jwku = require('../jwks-utils');

const jwkSet = require('./jwk_set.json');
const jwkSetPriv = require('./jwk_set_priv.json');
const jwk  = jwkSet.keys[0];
const jwk2 = jwkSet.keys[1];
let key = false;
let key2 = false;

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

describe('jwks-utils', function() {

  before(async () => {
    // Setup a couple of keys and a keystore to use:
    key  = await jose.JWK.asKey(jwkSetPriv.keys[0]);
    key2 = await jose.JWK.asKey(jwkSetPriv.keys[1]);
  });

  //-----------------------------------------------------------
  describe('#isJWK', function() {
    it('should return true for a JWK', function() {
      expect(jwku.isJWK(jwk)).to.equal(true);
    });

    it('should return false for object without "kty"', function() {
      expect(jwku.isJWK({foo: 'bar'})).to.equal(false);
    });
  });


  //-----------------------------------------------------------
  describe('#isJWKset', function() {
    it('should return true for a JWK Set', function() {
      expect(jwku.isJWKset(jwkSet)).to.equal(true);
    });

    it('should return false for object without "kty"', function() {
      expect(jwku.isJWKset({foo: 'bar'})).to.equal(false);
    });
  });


  //-----------------------------------------------------------
  describe('#findJWK', function() {
    it('should find JWK with matching "kid"', function() {
      var kid = jwk.kid;
      expect(jwku.findJWK(kid, jwkSet)).to.deep.equal(jwk);
    });

    it('shouldn\'t find a JWK for not matching "kid"', function() {
      expect(jwku.findJWK('non-existent', jwkSet)).to.equal(undefined);
    });

    it('should not find a JWK for undefined "kid"', function() {
      expect(jwku.findJWK(undefined, jwkSet)).to.be.not.ok;
    });
  });


  //-----------------------------------------------------------
  describe('#jwkForSignature', function() {
    const opts = {format: 'compact'}
    const payload = JSON.stringify('FOO BAR');
    it('should work with "jwk" JOSE header', async () => {
      const sig = await jose.JWS.createSign(opts, {key, header: {jwk}})
                  .update('FOO BAR').final();

      return expect(jwku.jwkForSignature(sig, false))
        .to.eventually.deep.equal(jwk);
    });

    it('should NOT work with "jku" JOSE header if hint is false (untrusted)', async () => {
      const sig = await jose.JWS.createSign(opts, {key, header: {
          jku: 'https://localhost:3000/jwks_uri',
          kid: jwk.kid,
      }}).update('FOO BAR').final();

      return expect(jwku.jwkForSignature(sig, false))
        .to.eventually.be.rejected;
    });

    it('should work with "jku" JOSE header if hint is a string and is the same as the jku header', async () => {
      const sig = await jose.JWS.createSign(opts, {key, header: {
          jku: 'https://localhost:3000/jwks_uri',
          kid: jwk.kid,
      }}).update('FOO BAR').final();

      return expect(jwku.jwkForSignature(sig, 'https://localhost:3000/jwks_uri'))
        .to.eventually.deep.equal(jwk);
    });

    it('should by default use the hint string to fetch the jwks instead of the jku on the header if they do not match', async () => {
      const sig = await jose.JWS.createSign(opts, {key, header: {
        jku: 'https://localhost:3000/does_not_exist',
        kid: jwk.kid,
      }}).update('FOO BAR').final();

      return expect(jwku.jwkForSignature(sig, 'https://localhost:3000/jwks_uri'))
        .to.eventually.deep.equal(jwk);
    });
     

    it('should work with URI hint', async () => {
      const sig = await jose.JWS.createSign(opts, {key, header: {
        kid: jwk.kid,
      }}).update('FOO BAR').final();

      return expect(jwku.jwkForSignature(sig, 'https://localhost:3000/jwks_uri'))
        .to.eventually.deep.equal(jwk);
    });

    it('should work with jwk hint', async () => {
      const sig = await jose.JWS.createSign(opts, {key, header: {
        kid: jwk.kid,
      }}).update('FOO BAR').final();

      return expect(jwku.jwkForSignature(sig, jwk))
        .to.eventually.deep.equal(jwk);
    });

    it('should work with jwks hint', async () => {
      const sig = await jose.JWS.createSign(opts, {key, header: {
        kid: jwk.kid,
      }}).update('FOO BAR').final();

      return expect(jwku.jwkForSignature(sig, jwkSet))
        .to.eventually.deep.equal(jwk);
    });

    it('should fail for invalid jwk/jwks hint', async () => {
      const sig = await jose.JWS.createSign(opts, {key, header: {
        kid: jwk.kid,
      }}).update('FOO BAR').final();

      return expect(jwku.jwkForSignature(sig, {}))
       .to.eventually.be.rejected;
    });

    it('should fail for invalid hints', async () => {
      const sig = await jose.JWS.createSign(opts, {key})
                        .update('FOO BAR').final();

      return expect(jwku.jwkForSignature(sig, true))
        .to.eventually.be.rejected;
    });

    it('should fail when JWKS URI can not be parsed', async () => {
      const sig = await jose.JWS.createSign(opts, {key})
                        .update('FOO BAR').final();

      return expect(jwku.jwkForSignature(sig, 'https://localhost:3000/jwks_uri_broken'))
        .to.eventually.be.rejected;
    });

    it('should fail when JWKS URI hosts an invalid JWK', async () => {
      const sig = await jose.JWS.createSign(opts, {key})
                        .update('FOO BAR').final();

      return expect(jwku.jwkForSignature(sig, 'https://localhost:3000/jwks_uri_invalid'))
        .to.eventually.be.rejected;
    });

    it('should timeout', async () => {
      const sig = await jose.JWS.createSign(opts, {key, header: {kid: jwk.kid} })
                        .update('FOO BAR').final();

      const options = { timeout: 1 };

      return expect(jwku.jwkForSignature(sig, 'https://localhost:3000/jwks_uri_slow', options))
        .to.eventually.be.rejected;
    });

    describe('with both "jku" and "jwk" JOSE headers', function() {
      it('should work when they agree', async () => {
        const sig = await jose.JWS.createSign(opts, {key, header: {
          jku: 'https://localhost:3000/jwks_uri',
          kid: jwk.kid,
          jwk,
        }}).update('FOO BAR').final();
  
        return expect(jwku.jwkForSignature(sig, 'https://localhost:3000/jwks_uri'))
          .to.eventually.deep.equal(jwk);
      });

      it('should error when they disagree', async () => {
        const sig = await jose.JWS.createSign(opts, {key, header: {
          jku: 'https://localhost:3000/jwks_uri',
          kid: jwk.kid,
          jwk: jwk2
        }}).update('FOO BAR').final();
 
        return expect(jwku.jwkForSignature(sig, 'https://localhost:3000/jwks_uri'))
          .to.eventually.be.rejected;
      });
    });

    it('should work with jku from cache when jku fails after first get', async () => {
      const jku_that_dies = 'https://localhost:3000/jwks_uri_dies_after_first_request';
      const resurrect_jku = 'https://localhost:3000/reset_jwks_uri_dies_after_first_request';

      return request.get(resurrect_jku)
      .then(async () => {
        const sig = await jose.JWS.createSign(opts, {key, header: {
          jku: jku_that_dies,
          kid: jwk.kid,
        }}).update('FOO BAR').final();
  
        return jwku.jwkForSignature(sig, jku_that_dies)
        .then(key => {
          // first request should be fine
          expect(key).to.deep.equal(jwk);
 
          return jwku.jwkForSignature(sig, jku_that_dies);
        }).then(key => expect(key).to.deep.equal(jwk));
      })
    });

  });


});
