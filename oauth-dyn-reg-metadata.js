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

var objectAssign = require('object-assign');
var jwt = require('jsonwebtoken');
// var pem_jwk = require('pem-jwk');
var JSCK = require('jsck');
var schema = require('./schemas/metadata.json');
var validator = new JSCK.draft4(schema);

function InvalidFormatException(message) {
    this.message = message;
    this.name = 'Invalid Format Exception';
}

/*
 generate client metadata
 A signed software statement containing
 client metadata values about the client software as claims
*/
function generate(metadata, key, options) {

    var softwareStatement = metadata['software_statement'];
    //TODO: make schema for the top level doc
    var err = validator.validate(softwareStatement);

    if (!err.valid) {
        throw new InvalidFormatException('Invalid software_statement');
    }

    options = options || {};
    options.payload = options.payload || {};

    objectAssign(options, {
        headers: {
            'typ': 'JWT',
            'alg': 'RS256'
        }
    });

    if (key.kid) {
        objectAssign(options, {
            headers: {
                'kid': key.kid
            }
        });
    }

    if (softwareStatement) {
        objectAssign(metadata, {
            'software_statement': jwt.sign(softwareStatement, key.pem, options)
        });
    }

    return metadata;
}

module.exports.generate = generate;
