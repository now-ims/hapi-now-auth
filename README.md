## hapi authentication plugin

[![Hapi Now Auth Test Runner](https://github.com/now-ims/hapi-now-auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/now-ims/hapi-now-auth/actions/workflows/ci.yml)

**Note:** this plugin is for [hapi](https://hapijs.com) v17+

This authentication package was inspired by [hapi-auth-bearer-token](https://github.com/johnbrett/hapi-auth-bearer-token) and [hapi-auth-jwt2](https://www.npmjs.com/package/hapi-auth-jwt2)

**hapi-now-auth** takes care of verifying your JWTs or bearer tokens. We will try to provide the best documentation possible, but reachout should you need help.

## Install

You can add the plugin to you project using npm or yarn:  
**npm:**`npm i @now-ims/hapi-now-auth`  
**yarn:**`yarn add @now-ims/hapi-now-auth`

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
- `options` (_Optional_)
  - `accessTokenName` - (_Default: `'authorization'`, Type: `string`_)
  - `allowQueryToken` - (_Default: `false`, Type: `boolean`_)
  - `allowCookieToken` - (_Default: `false`, Type: `boolean`_)
  - `allowMultipleHeaders` - (_Default: `false`, Type: `boolean`_) - accept multiple headers, e.g., Authorization Bearer \<token\>; Authorization JWT \<token\>
  - `tokenType` - (_Default: `Bearer`, Type: string_) - accept a custom token type e.g., Authorization JWT \<token\>
  - `allowChaining` - (_Default: `false`, Type: `boolean`_) - permit additional authentication strategies
  - `unauthorized` - (_Default: [Boom.unauthorized](https://github.com/hapijs/boom#boomunauthorizedmessage-scheme-attributes), Type: `function`_) - e.g., `function(message, scheme, attributes)`
  - `verifyJWT` - (_Default: `false`, Type: `boolean`_) - verify and decode JWT (_note:_ `validate` function will need to accept object of `{ decodedJWT, token }`)
  - `keychain` - (**Required** if verifyJWT: `True`, Type: `array[string]`) - an array of your secret keys
  - `verifyOptions` - (_Optional, Type: `object`_)
    - `algorithms` - (\*Default: `['HS256']`, Type: `array`)
    - `audience` - (_Optional, Type: `array`_) - if you want to check the audience `aud` supply an array to be checked
    - `issuer` - (_Optional, Type: `array`_) - array of strings of valid values for iss field
    - `ignoreExpiration` - (_Default: `false`, Type: `boolean`_) - ignore [`exp`](https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#expDef)
    - `ignoreNotBefore` - (_Default: `false`, Type: `boolean`_) - ignore [`nbf`](https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#nbfDef)
    - `subject` - (_Optional, Type: `string`_)
    - `clockTolerance` - (_Optional, Type: `integer`_) - number of seconds to tolerate when checking `nbf` or `exp` claims. _note: assists with minor clock differences_
    - `maxAge` - (_Optional, Type: `string`_) - maximum allowed age for tokens to still be valid - e.g., `2 days`, `1 hour`, `15m`
    - `clockTimestamp` - the time in seconds that should be used as current time for all necessary comparisons

## Working example

```js
const Hapi = require('hapi');
const HapiNowAuth = require('@now-ims/hapi-now-auth');

// create your hapi server
const server = Hapi.server({ port: 8000 });

// Start server function
async function start() {
  // register hapi-now-auth plugin
  try {
    await server.register(HapiNowAuth);
  } catch (error) {
    console.error(error);
    process.exit(1);
  }

  server.auth.strategy('jwt-strategy', 'hapi-now-auth', {
    verifyJWT: true,
    keychain: [process.env.SECRET_KEY],
    validate: async (request, token, h) => {
      let isValid, artifacts;

      /**
       * we asked the plugin to verify the JWT
       * we will get back the decodedJWT as token.decodedJWT
       * and we will get the JWT as token.token
       */

      const credentials = token.decodedJWT;

      /**
       * return the decodedJWT to take advantage of hapi's
       * route authentication options
       * https://hapijs.com/api#authentication-options
       */

      /**
       * Validate your token here
       * For example, compare to your redis store
       */

      redis.get(token, (error, result) => {
        if (error) {
          isValid = false;
          artifacts.error = error;
          return { isValid, credentials, artifacts };
        }
        isValid = true;
        artifacts.info = result;
        return { isValid, credentials, artifacts };
      });
    },
  });

  server.auth.default('jwt-strategy');

  server.route({
    method: 'GET',
    path: '/',
    handler: async (request, h) => {
      return { info: 'success!' };
    },
    options: {
      auth: false,
    },
  });

  server.route({
    method: 'GET',
    path: '/protected',
    handler: async (request, h) => {
      return { info: 'success if JWT is verified!' };
    },
  });

  server.route({
    method: 'GET',
    path: '/admin',
    handler: async (request, h) => {
      return { info: 'success if JWT is verified and scope includes admin' };
    },
    options: {
      auth: {
        scope: 'admin',
      },
    },
  });

  try {
    await server.start();
  } catch (error) {
    console.error(error);
    process.exit(1);
  }

  console.log(`Server running at: ${server.info.uri}`);
}

// Don't worry be hapi
start();
```

## Acknowledgement

This project is kindly sponsored by [Now IMS](https://nowims.com)

Licensed under [MIT](./LICENSE)
