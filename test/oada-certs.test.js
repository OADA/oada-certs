/* Copyright 2015 Open Ag Data Alliance
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

'use strict';

const _ = require('lodash');
const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
chai.use(chaiAsPromised);
const Promise = require('bluebird');
const expect = chai.expect;
const nock = require('nock');
const url = require('url');
const debug = require('debug');
const log = debug('oada-certs#test:trace');
const jose = require('node-jose');

// The module to be "checked" (i.e. under test)
const validate = require('../validate');
const sign = require('../sign');

// We will mock a server for the tests that use this URL:
const TEST_ROOT = 'https://test.example.org/';
const CUSTOM_TRUSTED_LIST = 'https://custom.trusted.list.com/';

// keypair used for signing in the tests:
const privJwk = require('./private.jwk.json');
let pubJwk = false;
let pubKey = false;

describe('oada-certs', function() {
  before(async () => {
    pubJwk = (await jose.JWK.asKey(privJwk)).toJSON(); // if you do not pass true to this function, it gives back only the public key
    pubKey = await jose.JWK.asKey(pubJwk);
  });

  //------------------------------------------------------------------------------------------
  // Testing generating keys (most of the generation tests are actually during validation)
  //------------------------------------------------------------------------------------------

  describe('oada-certs#sign', function() {
    const testpayload = 'DEAD BEEF';
    const key = _.cloneDeep(privJwk);
    it('should create a signature that verifies successfully with jose.JWS', async () => {
      const sig = await sign(testpayload, key);
      const {header, payload, signature} = await jose.JWS.createVerify(pubKey).verify(sig);
      expect(header.jwk).to.deep.equal(pubJwk);
      // payload from jose.JWS is a buffer, have to convert to string, then JSON.parse to get back to original because sign() stringifies it
      expect(testpayload).to.equal(JSON.parse(payload.toString()));
    });
    it('should create a signature that verifies successfully with jose.JWS using an object as a payload', async () => {
      const pld = { key1: testpayload };
      const sig = await sign(pld, key);
      const {header, payload, signature} = await jose.JWS.createVerify(pubKey).verify(sig);
      expect(header.jwk).to.deep.equal(pubJwk);
      // payload from jose.JWS is a buffer, have to convert to string, then JSON.parse to get back to original because sign() stringifies it
      expect(pld).to.deep.equal(JSON.parse(payload.toString()));
    });

    it('should create a signature that includes the jwk in the header even if there is a jku', async () => {
      const jku = 'https://some.url';
      const kid = pubJwk.kid;
      const sig = await sign(testpayload, key, { header: { jku, kid } });
      const {header, payload, signature} = await jose.JWS.createVerify(pubKey).verify(sig);
      expect(header.jwk).to.deep.equal(pubJwk);
      expect(header.jku).to.equal(jku);
      expect(header.kid).to.equal(kid);
    });

    it('should override the kid on a jwk if we pass one in the header', async () => {
      const jku = 'https://some.url';
      const kid = 'nottherealkid';
      const jwk = _.cloneDeep(pubJwk);
      jwk.kid = kid;
      const sig = await sign(testpayload, key, { header: { jku, kid } });
      const {header, payload, signature} = await jose.JWS.createVerify(pubKey).verify(sig);
      expect(header.jwk).to.deep.equal(jwk);
      expect(header.jku).to.equal(jku);
      expect(header.kid).to.equal(kid);
    });

  });
  
  
  //------------------------------------------------------------------------------------------
  // Testing validating keys
  //------------------------------------------------------------------------------------------
  
  describe('oada-certs#validate', function() {
    const payload = 'DEAD BEEF';
  
    // Setup the mock server to serve a trusted list with a URL for it's own jwk set 
    // When the main function tries to get the Trusted List, this will respond instead of github:
    beforeEach(function mockList() {
      const uri = url.parse(validate.TRUSTED_LIST_URI);
      nock(url.format({protocol: uri.protocol, host:uri.host}))
      .log(log)
      .get(uri.path)
      .reply(200, { version: "2", jkus: [ TEST_ROOT ], jwks: { keys: [] } });
  
      // Also host another identical one at a custom domain to test customizable trusted lists:
      const custom_uri = url.parse(CUSTOM_TRUSTED_LIST);
      nock(url.format({protocol: custom_uri.protocol, host: custom_uri.host}))
      .log(log)
      .get(custom_uri.path)
      .reply(200, { version: "2", jkus: [ TEST_ROOT ], jwks: { keys: [] } });
      // this is what version 1 trusted list looked like: .reply(200, [TEST_ROOT]);
    });
  
    // Setup the mock server to serve it's jwk set at the URL given in the mocked list above
    beforeEach(function mockJWKS() {
  
      // Setup the correct "trusted" one that's in mocked trusted list above:
      nock(TEST_ROOT)
      .log(log)
      //.filteringPath(function() { return '/'; })
  
      // For the root, it's in the trusted list:
      .get('/')
      .reply(200, {keys: [pubJwk]})
  
      // Also, host this one as the same list, but not considered trusted
      .get('/untrusted')
      .reply(200, { keys: [ pubJwk ] });
    });
  
    it('should return valid=false for invalid signature', async function() {
      // create a signature with private key = "FOO"
      let sig = await sign(payload, privJwk, {
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT
        }
      });
      const parts = sig.split('.');
      parts[2] = 'INVALIDSIGNATURE'; // the third item separated by periods is the signature in a JWT
      sig = parts.join('.');
      return validate(sig).then(result => {
        expect(result.trusted).to.equal(false);
        expect(result.valid).to.equal(false);
        expect(result.payload).to.deep.equal(payload);
      });
    });

    //--------------------------------------------------------------------
    describe('for valid but untrusted signature', async function() {
      it('should return trusted=false, valid=true if signature uses jku (but does have JWK in its headers) to avoid pinging maliciously', async () => {
        const sig = await sign(payload, privJwk, {
          header: {
            kid: privJwk.kid,
            jku: TEST_ROOT + 'untrusted',
          },
        });
        return validate(sig).then(result => {
          expect(result.trusted).to.equal(false);
          expect(result.valid).to.equal(true);
        });
      });
      it('should return trusted=false, valid=false if signature uses jku (and does NOT have JWK in its headers) to avoid pinging maliciously', async () => {
        const sig = await jose.JWS.createSign({ key: await jose.JWK.asKey(privJwk), header: {
          kid: privJwk.kid,
          jku: TEST_ROOT + 'untrusted',
        }}).update(payload).final();

        return validate(sig).then(result => {
          expect(result.trusted).to.equal(false);
          expect(result.valid).to.equal(false);
        });
      });

  
      it('should return trusted=false, valid=true if signature uses valid jwk', async () => {
        const sig = await sign(payload, privJwk, {
          header: {
            jwk: pubJwk,
          },
        });
        return validate(sig).then(result => {
          expect(result.trusted).to.equal(false);
          expect(result.valid).to.equal(true);
        });
      });
  
  
      it('should return the signature payload even though untrusted', async () => {
        const sig = await sign(payload, privJwk, {
          header: {
            kid: privJwk.kid,
            jku: TEST_ROOT + 'untrusted',
          },
        });
        return validate(sig).then(result => {
          expect(result.payload).to.equal(payload);
        });
      });
    });
  
    //--------------------------------------------------------------------
    describe('for valid trusted signature', function() {
      it('should return trusted=true, valid=true, header, payload', async () => {
        const sig = await sign(payload, privJwk, {
          header: {
            kid: privJwk.kid,
            jku: TEST_ROOT,
          },
        });
        return validate(sig).then(result => {
          expect(result.trusted).to.equal(true);
          expect(result.valid).to.equal(true);
          expect(result.payload).to.deep.equal(payload);
          expect(result.header).to.be.an('object');
          expect(result.header.kid).to.equal(privJwk.kid);
          expect(result.header.jku).to.equal(TEST_ROOT);
        });
      });
  
      it('should return the signature payload', async function() {
        const sig = await sign(payload, privJwk, {
          header: {
            kid: privJwk.kid,
            jku: TEST_ROOT,
          },
        });
        return validate(sig).then(result => {
          expect(result.payload).to.equal(payload);
        });
      });

      it('should return a matching signature payload for an object payload', async function() {
        const pld = { key1: payload };
        const sig = await sign(pld, privJwk, {
          header: {
            kid: privJwk.kid,
            jku: TEST_ROOT,
          },
        });
        return validate(sig).then(result => {
          expect(result.payload).to.deep.equal(pld);
        });
      });
    });
  
    describe('for customizing set of trusted lists', function() {
      it('should work for signature validation and be untrusted if no trusted lists exist: trusted is false and valid is true (because JWK is in header)', async function() {
        const sig = await sign(payload, privJwk, {
          header: {
            kid: privJwk.kid,
            jku: TEST_ROOT, // this would be considered trusted if trusted list was available
          },
        });
        // Disable default trusted list, and don't supply any others:
        return validate(sig, { disableDefaultTrustedListURI: true }).then(result => {
          expect(result.trusted).to.equal(false);
          expect(result.valid).to.equal(true);
        });
      });
      it('should work for customized trusted list that is down, returning false for trusted and true for valid (using JWK from header) because no public key can be found', async function() {
        const sig = await sign(payload, privJwk, {
          header: {
            kid: privJwk.kid,
            jku: TEST_ROOT, // this would be considered trusted if trusted list was available
          },
        });
        // Disable trusted list, and add a bad (down) trusted list:
        this.timeout(2000);
        return validate(sig, { 
          disableDefaultTrustedListURI: true,
          additionalTrustedListURIs: [ 'https://fakelist.is.down.and.never.will.return' ],
        }).then(result => {
          expect(result.trusted).to.equal(false);
          expect(result.valid).to.equal(true);
        });
      });
      it('should work for customized trusted list that is up', async function() {
        const sig = await sign(payload, privJwk, {
          header: {
            kid: privJwk.kid,
            jku: TEST_ROOT, // the new custom trusted list has this listed as trusted JKU
          },
        });
        // Disable default list, and use our custom one only:
        return validate(sig, { 
          disableDefaultTrustedListURI: true,
          additionalTrustedListURIs: [ CUSTOM_TRUSTED_LIST ],
        }).then(result =>{
          expect(result.trusted).to.equal(true);
          expect(result.valid).to.equal(true);
        });
      });
  
  
  
    });
  });
});


