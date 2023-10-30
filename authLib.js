const axios = require('axios');
const jwt = require('jsonwebtoken');
const forge = require('node-forge');

const certsPath = process.env.CERTS_PATH;
const certsPathSuffix = process.env.CERTS_PATH_SUFFIX;

function getPublicKeyPEMFromPublicKey(x5c) {
    const pemCertificates = `-----BEGIN CERTIFICATE-----\n${x5c}\n-----END CERTIFICATE-----\n`;
    // Parse the PEM certificates and extract the public key from the leaf certificate
    const leafCertificate = forge.pki.certificateFromPem(pemCertificates);
    const publicKey = leafCertificate.publicKey;
    // Convert the public key to PEM format
    const publicKeyPEM = forge.pki.publicKeyToPem(publicKey);

    return publicKeyPEM;
}

function createTokenVerifier(publicKeyPEM) {
    return function (token) {
        return jwt.verify(token, publicKeyPEM);
    }
}

async function getTokenVeriferFromIAMURL(iamIssuerURL) {
    const iamKeys = await axios(iamIssuerURL + certsPathSuffix);
    const keyToTokenVerifier = {};
    iamKeys.data.keys.forEach(key => {
        const kid = key.kid;
        const x5c = key.x5c;
        const publicKeyPEM = getPublicKeyPEMFromPublicKey(x5c);

        const tokenVerifier = createTokenVerifier(publicKeyPEM); 
        keyToTokenVerifier[kid] = tokenVerifier;
    });
    return keyToTokenVerifier;
}

// extract and return the Bearer Token from the Lambda event parameters
function getToken(params) {
    if (!params.type || params.type !== 'TOKEN') {
      throw new Error("Expected 'event.type' parameter to have value TOKEN");
    }
  
    var tokenString = params.authorizationToken;
    if (!tokenString) {
      throw new Error("Expected 'event.authorizationToken' parameter to be set");
    }
  
    var match = tokenString.match(/^Bearer (.*)$/);
    if (!match || match.length < 2) {
      throw new Error("Invalid Authorization token - '" + tokenString + "' does not match 'Bearer .*'");
    }
    return match[1];
}

function getDecodedToken(token) {
    return jwt.decode(token, { complete: true });
}

let keyToTokenVerifier = undefined;

module.exports.authenticate = async function (params) {
    const token = await getToken(params);
    const decodedToken = getDecodedToken(token);
    const kid = decodedToken.header.kid;
    const iss = decodedToken.payload.iss;

    if (iss != certsPath) {
        throw new Error(`unexpected iss`);
    }

    if (!keyToTokenVerifier) {
        keyToTokenVerifier = await getTokenVeriferFromIAMURL(certsPath);
    }

    try {
        const tokenVerifier = keyToTokenVerifier[kid];

        if (!tokenVerifier) {
            throw new Error(`token verifier not found`);
        }
        else {
            console.log("token verified successfully")
            const varefiedToken = tokenVerifier(token); // if token is invalid it will throw an exception
            return varefiedToken;
        }

    } catch (error) {
        console.error(error);
        throw new Error(`invalid token`);
    }
}