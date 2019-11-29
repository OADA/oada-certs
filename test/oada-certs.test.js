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

const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
chai.use(chaiAsPromised);
const Promise = require('bluebird');
const expect = chai.expect;
const nock = require('nock');
const url = require('url');
const jwt = require('jsonwebtoken');
const jwk2pem = require('pem-jwk').jwk2pem;
const debug = require('debug');
const log = debug('oada-certs#test:trace');

// The module to be "checked" (i.e. under test)
const check = require('../validate');

// We will mock a server for the tests that use this URL:
const TEST_ROOT = 'https://test.example.org/';
const CUSTOM_TRUSTED_LIST = 'https://custom.trusted.list.com/';

// keypair used for signing in the tests:
const privJwk = require('./private.jwk.json');
// A  public key is same as private key, but only keeping kid, n, e, and kty
const pubJwk = {
  kid: privJwk.kid,
    n: privJwk.n,
    e: privJwk.e,
  kty: privJwk.kty,
};


describe('oada-certs#validate', function() {
  const payload = 'DEAD BEEF';

  // Setup the mock server to serve a trusted list with a URL for it's own jwk set 
  // When the main function tries to get the Trusted List, this will respond instead of github:
  beforeEach(function mockList() {
    const uri = url.parse(check.TRUSTED_LIST_URI);
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

  it('should return valid=false for invalid signature', function() {
    // create a signature with private key = "FOO"
    const sig = jwt.sign(payload, 'FOO', {
      algorithm: 'HS256',
      header: {
        kid: privJwk.kid,
        jku: TEST_ROOT
      }
    });
    return check(sig).then(result => {
      expect(result.trusted).to.equal(false);
      expect(result.valid).to.equal(false);
      expect(result.clientcert).to.deep.equal(payload);
    });
  });

  //--------------------------------------------------------------------
  describe('for valid but untrusted signature', function() {
    it('should return trusted=false, valid=false if signature uses jku to avoid pinging maliciously', () => {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT + 'untrusted',
        },
      });
      return check(sig).then(result => {
        expect(result.trusted).to.equal(false);
        expect(result.valid).to.equal(false);
      });
    });

    it('should return trusted=false, valid=true if signature uses valid jwk', () => {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          jwk: pubJwk,
        },
      });
      return check(sig).then(result => {
        expect(result.trusted).to.equal(false);
        expect(result.valid).to.equal(true);
      });
    });


    it('should return the signature payload even though untrusted', () => {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT + 'untrusted',
        },
      });
      return check(sig).then(result => {
        expect(result.clientcert).to.equal(payload);
      });
    });
  });

  //--------------------------------------------------------------------
  describe('for valid trusted signature', function() {
    it('should return trusted=true, valid=true', () => {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT,
        },
      });
      return check(sig).then(result => {
        expect(result.trusted).to.equal(true);
        expect(result.valid).to.equal(true);
      });
    });

    it('should return the signature payload', function() {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT,
        },
      });
      return check(sig).then(result => {
        expect(result.clientcert).to.equal(payload);
      });
    });
  });

  describe('for customizing set of trusted lists', function() {
    it('should work for signature validation and be untrusted if no trusted lists exist', function() {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT, // this would be considered trusted if trusted list was available
        },
      });
      // Disable default trusted list, and don't supply any others:
      return check(sig, { disableDefaultTrustedListURI: true }).then(result => {
        expect(result.trusted).to.equal(false);
        expect(result.valid).to.equal(true);
      });
    });
    it('should work for customized trusted list that is down, returning false for trusted', function() {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT, // this would be considered trusted if trusted list was available
        },
      });
      // Disable trusted list, and add a bad (down) trusted list:
      this.timeout(2000);
      return check(sig, { 
        disableDefaultTrustedListURI: true,
        additionalTrustedListURIs: [ 'https://fakelist.is.down.and.never.will.return' ],
      }).then(result => {
        expect(result.trusted).to.equal(false);
        expect(result.valid).to.equal(true);
      });
    });
    it('should work for customized trusted list that is up', function() {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT, // the new custom trusted list has this listed as trusted JKU
        },
      });
      // Disable default list, and use our custom one only:
      return check(sig, { 
        disableDefaultTrustedListURI: true,
        additionalTrustedListURIs: [ CUSTOM_TRUSTED_LIST ],
      }).then(result =>{
        expect(result.trusted).to.equal(true);
        expect(result.valid).to.equal(true);
      });
    });



  });
});
