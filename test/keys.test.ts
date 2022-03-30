/**
 * @licenses
 * Copyright 2015 Open Ag Data Alliance
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

import test from 'ava';

// The module to be "checked" (i.e. under test)
import { create, pubFromPriv } from '../dist/keys.js';

test('create', async (t) => {
  const k = await create();
  t.assert(typeof k.public === 'object', 'should create a public key');
  t.assert(typeof k.private === 'object', 'should create a private key');
});

test('pubFromPriv', async (t) => {
  const k = await create();
  const pub = await pubFromPriv(k.private);
  t.deepEqual(
    pub,
    k.public,
    'should return a public key given a valid private one'
  );
});
