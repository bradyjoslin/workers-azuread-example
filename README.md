**Fork of [signalnerve/workers-auth0-example](https://github.com/signalnerve/workers-auth0-example) for targeting Azure AD instead of Auth0.**

---

<div align="center">
<h1>🔐🙅‍♀️ workers-azuread-example</h1>
<p>authorization/authentication at the edge, using <a href="https://workers.dev">cloudflare workers</a> and <a href="https://azure.microsoft.com/en-us/services/active-directory/">Azure AD</a></p>
</div>

## prerequisites

- a cloudflare workers unlimited account
- an Azure AD account and a configured application
- if deploying in front of a domain, a configured cloudflare zone (see the "origin" section of "deploys" below)
- [`wrangler`](https://github.com/cloudflare/wrangler) cli tool installed and configured (see the [quick start](https://developers.cloudflare.com/workers/quickstart/) in the docs)

## getting started

using `wrangler`, you can generate a new project using this repo:

`wrangler generate my-auth-example https://github.com/bradyjoslin/workers-azuread-example`

## setup

this project makes heavy use of `wrangler`, the workers command-line tool, for managing environment variables and deploying this codebase. before trying to deploy this project, i recommend closely following this section of the readme to get all the relevant tokens, ids, and values that you'll need to successfully deploy this project.

### `wrangler.toml`

the `wrangler.toml` config file in this repository needs to be configured for deploying your own version of this application. using `wrangler generate` will automatically add a `name` field - you'll also need to configure an account id, and, depending on if you're deploying your application to a _zone_ (see "deploying" later in this readme), a zone id and route.

for more information on configuring this correctly, i strongly recommend you check out the [quick start](https://developers.cloudflare.com/workers/quickstart/) in the workers docs!

#### kv namespace creation

by default, this project uses the binding `AUTH_STORE` to refer to a kv namespace where credentials are read/written from the workers script. to create your own kv namespace, use `wrangler`, and copy the resulting id into the `kv-namespaces` portion of `wrangler.toml`:

```
wrangler kv:namespace create AUTH_STORE
```

### secrets

below is a table of secrets that the workers script will look for when it processes a client request. each should be set with `wrangler secret`:

| wrangler secret key | value                                                                                           |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| AAD_DOMAIN          | your Azure AD domain with your tenant id (e.g. `https://login.microsoftonline.com/{tenant_id}`) |
| AAD_CLIENT_ID       | your Azure AD client id                                                                         |
| AAD_CLIENT_SECRET   | your Azure AD client secret                                                                     |
| AAD_CALLBACK_URL    | the callback url for your application (see below)                                               |
| PASSWORD            | A secret string used to encrypt stored tokens using `encrypt-workers-kv`                        |

### setting the callback url

in order to correctly set the callback url for your application, you will need to determine where your application will be deployed. regardless of whether you're setting up a _originless_ or _origin_-based deploy, the callback handler for this project is defined at `/auth`. this means that if you're testing or deploying a staging version of this project, your callback url will likely be something like `https://my-auth-example.signalnerve.workers.dev/auth`, or for production, you should set it to something like `https://my-production-app.com/auth`.

## configuration

this application features a growing number of configuration options available via the `config` object in `index.js`. these can be customized to toggle different features in the script, and are outlined below (with callouts to more detailed explanations, further in the readme):

### `config.hydrateState`

enable authorization state hydration, to pass user info such as name and email to your application. see "edge state hydration" later in the readme.

### `config.originless`

serve responses directly from the edge, without the need for an origin server. see "deploying" later in the readme.

## edge state hydration

by default, any information stored in Azure AD, such as your user's name, email, or other custom values can be inlined into your website's response by defining `script#edge_state` tag in the `head` section of your static site. workers' `htmlrewriter` will inline the provided state into that tag as a JSON string. you can opt into this feature by pasting something similar to the below snippet:

```html
<script id="edge_state" type="application/json">
  {}
</script>
```

note that if you'd like to disable this feature, you can toggle the config option `hydrateState` to `false`.

## deploying

`wrangler publish`

### originless

by default, this codebase is deployed without an origin - we call this "originless" - and can be used to serve responses "from the edge". this means that your application can be authenticated/authorized at a cloudflare edge server close to your users, which can make a huge impact on latency.

this project uses `workers sites` to serve static websites from the edge. by default, any assets in the `public` folder will be uploaded to workers kv, and used to serve your static site to users. if you'd like to change this from `public`, modify the `site.bucket` field in `wrangler.toml` to point to your application. if you're using `gatsby` or similar static site frameworks, this should represent the _final, compiled_ version of your site.

### origin

if you'd like to authorize/authenticate users at the edge, but still return a response from an origin server, set `config.originless` to `false`. this requires that your workers script is deployed to a zone (see ["configure" and "publish to your domain" in the cloudflare workers quick start](https://developers.cloudflare.com/workers/quickstart/)). _this hasn't been tested and may be broken. sorry, coming soon!_

## issues

please file issues for bugs and feature requests on this project! note that this repo isn't a good place to get help with wrangler, cloudflare workers, or other specific platform issues: check out the [workers forums](https://community.cloudflare.com/c/developers/workers/40).

## license

mit

## references

- [Microsoft identity platform and OAuth 2.0 authorization code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- [htmlrewriter](https://developers.cloudflare.com/workers/reference/apis/html-rewriter/)
- [quick start](https://developers.cloudflare.com/workers/quickstart)
- [workers sites](https://developers.cloudflare.com/workers/sites)
- [wrangler](https://github.com/cloudflare/wrangler)
- [wrangler dev](https://github.com/cloudflare/wrangler#-dev)
- [encrypt-workers-kv](https://github.com/bradyjoslin/encrypt-workers-kv)
