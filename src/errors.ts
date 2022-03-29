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
export class InvalidFormatException extends Error {
  readonly errors: readonly Error[];
  constructor(message: string, errors: Error[] = []) {
    super(message);
    this.name = 'Invalid Format Exception';
    this.errors = errors;
  }
}

export class InvalidKeyException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Invalid Key Exception';
  }
}

export class SignatureFailedException extends Error {
  readonly errors: readonly Error[];
  constructor(message: string, errors: Error[] = []) {
    super(message);
    this.name = 'Signature Failed Exception';
    this.errors = errors;
  }
}
