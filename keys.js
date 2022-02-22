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

const jose = require('node-jose');
const uuid = require('uuid').v4;

async function create() {
  const k = await jose.JWK.createKey('RSA', 2048, {
    kid: uuid().replace(/-/g, ''),
  }); // Assign a random string ID (I don't like the dashes in uuids)
  return {
    public: k.toJSON(),
    private: k.toJSON(true),
  };
}

async function pubFromPriv(privJWK) {
  const k = await jose.JWK.asKey(privJWK);
  return k.toJSON(); // If you don't pass true to this function, you get back just the public key
}

module.exports = {
  create,
  pubFromPriv,
};
