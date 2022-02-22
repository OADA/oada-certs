/**
 * @license
 * Copyright 2022 Open Ag Data Alliance
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

// There are many reasons why the format may be invalid, pass all errors on
// 'errors' array attached to the Error
module.exports = {
  InvalidFormatException(message, errors) {
    this.message = message;
    this.name = 'Invalid Format Exception';
    this.errors = errors;
    this.stack = new Error('Invalid format exception').stack;
  },

  InvalidKeyException(message) {
    this.message = message;
    this.name = 'Invalid Key Exception';
    this.stack = new Error('Invalid Key Exception').stack;
  },

  SignatureFailedException(message, errors) {
    this.message = message;
    this.name = 'Signature Failed Exception';
    this.errors = errors;
    this.stack = new Error('Signature Failed Exception').stack;
  },
};
