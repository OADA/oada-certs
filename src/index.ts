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

// Sign a client certificate:
export { sign } from './sign.js';

// Validate a client certificate (also check trusted):
export * as validate from './validate.js';

// Handy JWK utilities like jwkForSignature and decodeWithoutVerify
export * as jwksUtils from './jwks-utils.js';

// Wrapper for node-jose to create an RSA public/private keypair for you (2048 bit key length)
export * as keys from './keys.js';
