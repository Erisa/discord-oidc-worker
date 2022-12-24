# Discord OIDC Provider for Cloudflare Access

Simply put: Allows you to authorise with Cloudflare Access using your Discord account via a Cloudflare Worker. Wraps OIDC around the Discord OAuth2 API to achieve this, storing signing keys in KV. 

Process flow was inspired by [kimcore/discord-oidc](https://github.com/kimcore/discord-oidc) but rewritten entirely for [Cloudflare Workers](https://workers.cloudflare.com/) and [Hono](https://honojs.dev/).

Some ideas were also taken from [eidam/cf-access-workers-oidc](https://github.com/eidam/cf-access-workers-oidc).

Show them some love!

## Setup

You will need a [Discord developer application](https://discord.com/developers/applications) to use for OAuth2 and a Cloudflare Access account to setup with. When creating this Discord developer application set the redirect URL to your Cloudflare Access subdomain followed by `cdn-cgi/access/callback`. You will also need NodeJS.

- Clone the repository.
- Install dependencies: `npm install`
- Create a KV namespace on Cloudflare [here](https://dash.cloudflare.com/?to=/:account/workers/kv/namespaces).
- Edit `wrangler.toml` to use your new KV namespace ID.
- Copy `config.sample.json` to `config.json`.
- Add your Discord application ID and OAuth2 secret to `config.json`.
- Edit your Cloudflare Access subdomain into `config.json` under `redirectURL`.
- Publish the Worker with `npx wrangler publish`!

## Usage

- Go to the [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com)
- Navigate to Settings > Authentication, select "Add new" under Login methods, select OpenID Connect.
- Fill the following fields:
    - Name: Whatever you want, e.g. `Discord`
    - App ID: Your Discord application ID.
    - Client secret: Your Discord application OAuth2 secret.
    - Auth URL: `https://discord-oidc.YOURNAME.workers.dev/authorize/email` or swap out `/email` for `/guilds` to include the Guilds scope.
    - Token URL:  `https://discord-oidc.YOURNAME.workers.dev/token`
    - Certificate URL: `https://discord-oidc.YOURNAME.workers.dev/jwks.json`
    - Proof Key for Code Exchange (PKCE): Enabled
    - OIDC Claims:
        - Email is included automatically without being set here.
        - `preferred_username` will map to the users name + discrim e.g. `Erisa#9999`
        - If the Auth URL is `/guilds` then the `guilds` claim can be used toprovide a list of guild IDs.
        - Anything else from here will work: https://discord.com/developers/docs/resources/user#user-object-user-structure

My setup, as an example:

![](https://up.erisa.uk/firefox_5978jWH1ti.png)

To use this in a policy, simply enable it as an Identity provider in your Access application and then create a rule using `OIDC Claims` and the relevant claim above. Make sure the claim has been added to your provider in the steps above.

This example would allow me to access the application if I was myself on Discord or if I was a member of a specific server:
![](https://up.erisa.uk/firefox_1w0BXtk80X.png)

## Security

If you find a security vulnerability in this repository, do NOT create an Issue or Pull Request. Please contact me through email or message (There are links on my GitHub profile). If you create an issue for an active security vulnerability I will save the information and delete the issue.
