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

// The module to be "checked" (i.e. under test)
const keys = require('../keys');

describe('oada-certs.keys', () => {
  describe('oada-certs.keys#create', () => {
    it('should create a public and private key', async () => {
      const k = await keys.create();
      expect(k.public).to.be.an('object');
      expect(k.private).to.be.an('object');
    });
  });
  describe('oada-certs.keys#pubFromPriv', () => {
    it('should return a public key given a valid private one', async () => {
      const k = await keys.create();
      const pub = await keys.pubFromPriv(k.private);
      expect(pub).to.deep.equal(k.public);
    });
  });
});
