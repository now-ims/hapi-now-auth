## hapi authentication plugin

[![Build Status](https://travis-ci.org/puchesjr/hapi-now-auth.svg?branch=master)](https://travis-ci.org/puchesjr/hapi-now-auth)

**Note:** this plugin is for [hapi](https://hapijs.com) v17+ 

This authentication package was inspired by [hapi-auth-bearer-token](https://github.com/johnbrett/hapi-auth-bearer-token) and [hapi-auth-jwt2](https://www.npmjs.com/package/hapi-auth-jwt2)

**hapi-now-auth** takes care of verifying your JWTs or bearer tokens. We will try to provide the best documentation possible, but reachout should you need help.

## Install
You can add the plugin to you project using npm or yarn:  
**npm:**```npm i @now-ims/hapi-now-auth```  
**yarn:**```yarn add @now-ims/hapi-now-auth```  

## Hapi Now Auth Scheme  
This plugin creates a `hapi-now-auth` [authentication scheme](https://hapijs.com/api#authentication-scheme) with the following options:  
- `validate` - **(required)** your validation function with `[async] function(request, token, h)` where:
  - `request` is the [hapi request object](https://hapijs.com/api#request)
  - `token` 
    - `if (verifyJWT === false)`
      - the auth token received from the client
    - `if (verifyJWT === true)`
      - object `{ decodedJWT, token }`
  - `h` the [hapi response toolkit](https://hapijs.com/api#response-toolkit)
  - **Response**
    - `{ isValid, credentials, artifacts }` where:
      - `isValid` true if `JWT` or `Bearer` token is valid
      - `credentials` an object passed back to your application in `request.auth.credentials`
      - `artifacts` optional related data
- `options` (*Optional*)
  - `accessTokenName` - (*Default: `'access_token'`, Type: `string`*) 
  - `allowQueryToken` - (*Default: `false`, Type: `boolean`*)
  - `allowCookieToken` - (*Default: `false`, Type: `boolean`*)
  - `allowMultipleHeaders` - (*Default: `false`, Type: `boolean`*) - accept multiple headers, e.g., Authorization Bearer \<token\>; Authorization JWT \<token\>
  - `tokenType` - (*Default: `Bearer`, Type: string*) - accept a custom token type e.g., Authorization JWT \<token\>
  - `allowChaining` - (*Default: `false`, Type: `boolean`*) - permit additional authentication strategies
  - `unauthorized` - (*Default: [Boom.unauthorized](https://github.com/hapijs/boom#boomunauthorizedmessage-scheme-attributes), Type: `function`*) - e.g., `function(message, scheme, attributes)`
  - `verifyJWT` - (*Default: `false`, Type: `boolean`*) - verify and decode JWT (*note:* `validate` function will need to accept object of `{ decodedJWT, token }`)
  - `keychain` - (**Required** if verifyJWT: `True`, Type: `array[string]`) - an array of your secret keys
  - `verifyOptions` - (*Optional, Type: `object`*)
    - `algorithms` - (*Default: `['HS256']`, Type: `array`)
    - `audience` - (*Optional, Type: `array`*) - if you want to check the audience `aud` supply an array to be checked
    - `issuer` - (*Optional, Type: `array`*) - array of strings of valid values for iss field
    - `ignoreExpiration` - (*Default: `false`, Type: `boolean`*) - ignore [`exp`](https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#expDef)
    - `ignoreNotBefore` - (*Default: `false`, Type: `boolean`*) - ignore [`nbf`](https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#nbfDef)
    - `subject` - (*Optional, Type: `string`*)
    - `clockTolerance` - (*Optional, Type: `integer`*) - number of seconds to tolerate when checking `nbf` or `exp` claims. *note: assists with minor clock differences*
    - `maxAge` - (*Optional, Type: `string`*) - maximum allowed age for tokens to still be valid - e.g., `2 days`, `1 hour`, `15m`
    - `clockTimestamp` - the time in seconds that should be used as current time for all necessary comparisons

## Working example  
```
const Hapi = require('hapi');
const HapiNowAuth = require('hapi-now-auth');

// create your hapi server
const server = Hapi.server({ port: 8000 });

// Start server function
async function start() {

    // register hapi-now-auth plugin
    try {
        await server.register(HapiNowAuth);
    }
    catch (error) {
        console.error(error);
        process.exit(1);
    }

    server.auth.strategy('my-strategy', 'hapi-now-auth', {
        verifyJWT: true,
        keychain: [process.env.SECRET_KEY],
        validate: async (request, token, h) => {
            let isValid, artifacts;

            const credentials = { token };
            
            /**
             * Validate your token here
             * For example, compare to your redis store
             */
             redis.get(token, (error, result) => {
                 if (error) {
                     isValid = false;
                     artifacts.error = error
                     return { isValid, credentials, artifacts };
                 }
                 isValid = true;
                 artifacts.info = result;
                 return { isValid, credentials, artifacts }
             })
        }
    });

    server.auth.default('my-strategy');

    server.route({
        method: 'GET',
        path: '/',
        handler: async (request, h) => {

            return { info: 'success!' }
        }
    });

    try {
        await server.start();
    }
    catch (error) {
        console.error(error);
        process.exit(1);
    }

    console.log(`Server running at: ${server.info.uri}`);

};

// Don't worry be hapi
start();
```
License MIT