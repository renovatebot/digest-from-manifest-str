/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2017 Joyent, Inc.
 */

const base64url = require('base64url');
const crypto = require('crypto');
const jwkToPem = require('jwk-to-pem');

function jwsFromManifest(manifest, body) {
  let formatLength;
  let formatTail;
  const jws = {
    signatures: [],
  };

  for (let i = 0; i < manifest.signatures.length; i += 1) {
    const sig = manifest.signatures[i];
    const protectedHeader = JSON.parse(base64url.decode(sig.protected));
    if (Number.isNaN(protectedHeader.formatLength)) {
      throw new Error();
    } else if (formatLength === undefined) {
      formatLength = protectedHeader.formatLength; // eslint-disable-line prefer-destructuring
    } else if (protectedHeader.formatLength !== formatLength) {
      throw new Error();
    }

    if (
      !protectedHeader.formatTail
      || typeof protectedHeader.formatTail !== 'string'
    ) {
      throw new Error();
    }
    const res = base64url.decode(protectedHeader.formatTail);
    if (res === undefined) {
      formatTail = res;
    } else if (formatTail !== res) {
      throw new Error();
    }

    const jwsSig = {
      header: {
        alg: sig.header.alg,
        chain: sig.header.chain,
      },
      signature: sig.signature,
      protected: sig.protected,
    };
    if (sig.header.jwk) {
      try {
        jwsSig.header.jwk = jwkToPem(sig.header.jwk);
      } catch (jwkErr) {
        throw new Error();
      }
    }
    jws.signatures.push(jwsSig);
  }

  jws.payload = Buffer.concat([
    body.slice(0, formatLength),
    Buffer.from(formatTail),
  ]);

  return jws;
}

/**
 * Calculate the 'Docker-Content-Digest' header for the given manifest.
 *
 * @returns {String} The docker digest string.
 * @throws {InvalidContentError} if there is a problem parsing the manifest.
 */
function digestFromManifestStr(manifestStr) {
  const hash = crypto.createHash('sha256');
  const digestPrefix = 'sha256:';

  let manifest;
  try {
    manifest = JSON.parse(manifestStr);
  } catch (err) {
    throw new Error('Could not parse manifestStr');
  }
  if (manifest.schemaVersion === 1) {
    const manifestBuffer = Buffer.from(manifestStr);
    const jws = jwsFromManifest(manifest, manifestBuffer);
    hash.update(jws.payload, 'binary');
    return digestPrefix + hash.digest('hex');
  }
  hash.update(manifestStr);
  return digestPrefix + hash.digest('hex');
}

module.exports = {
  digestFromManifestStr,
};
