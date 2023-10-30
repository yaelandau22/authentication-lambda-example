'use strict';

var authLib = require('./authLib');

var generatePolicy = function(principalId, effect, resource) {
  var authResponse = {};
  
  authResponse.principalId = principalId;
  if (effect && resource) {
      var policyDocument = {};
      policyDocument.Version = '2012-10-17'; 
      policyDocument.Statement = [];
      var statementOne = {};
      statementOne.Action = 'execute-api:Invoke'; 
      statementOne.Effect = effect;
      statementOne.Resource = resource;
      policyDocument.Statement[0] = statementOne;
      authResponse.policyDocument = policyDocument;
  }

  return authResponse;
}

module.exports.handler = async ( event, context, callback) => {
  console.log('event', event);
    try {
      const authenticateResponse = await authLib.authenticate(event);
      let authResponse = generatePolicy('user', 'Allow', event.methodArn);
      return callback(null, authResponse);
    } catch (error) {
      console.error('User is not authorized', event);
      return callback('Unauthorized');
    }
};