import * as config from './config.json'
import { Hono } from 'hono'
import * as jose from 'jose'

const algorithm = {
	name: 'RSASSA-PKCS1-v1_5',
	modulusLength: 2048,
	publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
	hash: { name: 'SHA-256' },
}

const importAlgo = {
	name: 'RSASSA-PKCS1-v1_5',
	hash: { name: 'SHA-256' },
}

async function loadOrGenerateKeyPair(KV) {
	let keyPair = {}
	let keyPairJson = await KV.get('keys', { type: 'json' })

	if (keyPairJson !== null) {
		keyPair.publicKey = await crypto.subtle.importKey('jwk', keyPairJson.publicKey, importAlgo, true, ['verify'])
		keyPair.privateKey = await crypto.subtle.importKey('jwk', keyPairJson.privateKey, importAlgo, true, ['sign'])

		return keyPair
	} else {
		keyPair = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])

		await KV.put('keys', JSON.stringify({
			privateKey: await crypto.subtle.exportKey('jwk', keyPair.privateKey),
			publicKey: await crypto.subtle.exportKey('jwk', keyPair.publicKey)
		}))

		return keyPair
	}

}

const app = new Hono()

app.get('/authorize/:scopemode', async (c) => {

	if (c.req.query('client_id') !== config.clientId
		|| c.req.query('redirect_uri') !== config.redirectURL
		|| !['guilds', 'email', 'roles'].includes(c.req.param('scopemode'))) {
		return c.text('Bad request.', 400)
	}

	let scopes = '';
	
	switch(c.req.param('scopemode')) {
		case 'email':
			scopes = 'identify email'
			break;
		case 'guilds':
			scopes = 'identify email guilds'
			break;
		case 'roles':
			scopes = 'identify email guilds guilds.members.read'
			break;
		default:
			return c.text('Bad request.', 400)
	}

	const params = new URLSearchParams({
		'client_id': config.clientId,
		'redirect_uri': config.redirectURL,
		'response_type': 'code',
		'scope': scopes,
		'state': c.req.query('state'),
		'prompt': 'none'
	}).toString()

	return c.redirect('https://discord.com/oauth2/authorize?' + params)
})

app.post('/token', async (c) => {
	const body = await c.req.parseBody()
	const code = body['code']
	const params = new URLSearchParams({
		'client_id': config.clientId,
		'client_secret': config.clientSecret,
		'redirect_uri': config.redirectURL,
		'code': code,
		'grant_type': 'authorization_code'
	}).toString()

	const r = await fetch('https://discord.com/api/oauth2/token', {
		method: 'POST',
		body: params,
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			'User-Agent': 'DiscordBot (https://github.com/Erisa/discord-oidc-worker, v1.0.0)'
		}
	}).then(res => res.json())
	
	if (r === null) return new Response("Bad request.", { status: 400 })

	const returned_scope = r['scope'].split(' ')
	
	const userInfo = await fetch('https://discord.com/api/users/@me', {
		headers: {
			'Authorization': 'Bearer ' + r['access_token'],
			'User-Agent': 'DiscordBot (https://github.com/Erisa/discord-oidc-worker, 1.0.0)'
		}
	}).then(res => res.json())

	if (!userInfo['verified']) return c.text('Bad request.', 400)

	let servers = []

	if (returned_scope.includes('guilds')) {
		const serverResp = await fetch('https://discord.com/api/users/@me/guilds', {
			headers: {
				'Authorization': 'Bearer ' + r['access_token'],
				'User-Agent': 'DiscordBot (https://github.com/Erisa/discord-oidc-worker, v1.0.0)'
			}
		})
	
		if (serverResp.status === 200) {
			const serverJson = await serverResp.json()
			servers = serverJson.map(item => {
				return item['id']
			})
		}
	}

	let roleClaims = {}

	if (config.cacheRoles) {
		if ('serversToCheckRolesFor' in config) {
			console.log("Servers to check roles for: " + config.serversToCheckRolesFor)
			await Promise.all(config.serversToCheckRolesFor.map(async guildId => {
				const roleCache = await getRolesFromCacheFor(c.env, guildId, userInfo['id'])
				if (roleCache != null) {
					roleClaims[`roles:${guildId}`] = roleCache
				}
			}))
		}
	} else if (returned_scope.includes('guilds.members.read')) {
		if ('serversToCheckRolesFor' in config) {
			await Promise.all(config.serversToCheckRolesFor.map(async guildId => {
				if (servers.includes(guildId)) {
					let memberPromise = fetch(`https://discord.com/api/users/@me/guilds/${guildId}/member`, {
						headers: {
							'Authorization': 'Bearer ' + r['access_token'],
							'User-Agent': 'DiscordBot (https://github.com/Erisa/discord-oidc-worker, v1.0.0)'
						}
					})
					
					const memberResp = await memberPromise
					const memberJson = await memberResp.json()
					
					roleClaims[`roles:${guildId}`] = memberJson.roles
				}
			}))
		}
	} else {
		if (c.env.DISCORD_TOKEN && 'serversToCheckRolesFor' in config) {
			await Promise.all(config.serversToCheckRolesFor.map(async guildId => {
				if (servers.includes(guildId)) {
					let memberPromise = fetch(`https://discord.com/api/guilds/${guildId}/members/${userInfo['id']}`, {
						headers: {
							'Authorization': 'Bot ' + c.env.DISCORD_TOKEN,
							'User-Agent': 'DiscordBot (https://github.com/Erisa/discord-oidc-worker, v1.0.0)'
						}
					})
					
					const memberResp = await memberPromise
					const memberJson = await memberResp.json()

					roleClaims[`roles:${guildId}`] = memberJson.roles
				}
			}))
		}
	}

	const idToken = await new jose.SignJWT({
		iss: 'https://cloudflare.com',
		aud: config.clientId,
		preferred_username: `${userInfo['username']}#${userInfo['discriminator']}`,
		...userInfo,
		...roleClaims,
		email: userInfo['email'],
		guilds: servers
	})
		.setProtectedHeader({ alg: 'RS256' })
		.setExpirationTime('1h')
		.setAudience(config.clientId)
		.sign((await loadOrGenerateKeyPair(c.env.KV)).privateKey)

	return c.json({
		...r,
		scope: 'identify email',
		id_token: idToken
	})
})

app.get('/jwks.json', async (c) => {
	let publicKey = (await loadOrGenerateKeyPair(c.env.KV)).publicKey
	return c.json({
		keys: [{
			alg: 'RS256',
			kid: 'jwtRS256',
			...(await crypto.subtle.exportKey('jwk', publicKey))
		}]
	})
})

async function getRolesFromCacheFor(env, guildId, memberId) {
	let memberRoleCache = await env.KV.get(`roles:${guildId}`, { type: "json" })
	if (memberRoleCache != null && memberId in memberRoleCache) {
		return memberRoleCache[memberId]
	}
	return null
}

async function cacheRoles(event, env) {
	console.log("Triggered cacheRoles")
	if (config.cacheRoles && env.DISCORD_TOKEN && 'serversToCheckRolesFor' in config) {
		console.log("Executing cacheRoles")
		
		let memberRoleCache = {}

		await Promise.all(config.serversToCheckRolesFor.map(async guildId => {
			let tempMemberList = []
			let last = 0
			let recd = 1000

			while(recd > 0) {
				let incrMemberPromise = fetch(`https://discord.com/api/guilds/${guildId}/members?` + new URLSearchParams({
					limit: 1000,
					after: last
				}).toString(), {
					headers: {
						'Authorization': 'Bot ' + env.DISCORD_TOKEN,
						'User-Agent': 'DiscordBot (https://github.com/Erisa/discord-oidc-worker, v1.0.0)'
					}
				})
				let incrMemberResp = await incrMemberPromise
				// That might work as a minified ratelimit handler
				if (incrMemberResp.status != 200) {
					// wait 10 seconds and try again
					await new Promise(resolve => setTimeout(resolve, 10000))
					incrMemberResp = await incrMemberPromise
				}

				const incrMemberJson = await incrMemberResp.json()
				recd = incrMemberJson.length
				if (recd == 0) {
					last = 0
				} else {
					incrMemberJson.map(item => {
						tempMemberList.push(item)
					})
					last = incrMemberJson[recd - 1]['user']['id']
				}
			}
			
			memberRoleCache[guildId] = {}
			tempMemberList.map(item => {
				memberRoleCache[guildId][item['user']['id']] = item['roles']
			})
			await env.KV.put(`roles:${guildId}`, JSON.stringify(memberRoleCache[guildId]), { expirationTtl: 3600 })
			console.log("Cached roles for " + Object.keys(memberRoleCache[guildId]).length + " members in " + guildId)
		}))
		console.log("Cached roles for " + Object.keys(memberRoleCache).length + " servers")
	} else {
		console.log("Skipping cacheRoles")
	}
}

export default {
	async fetch(request, env, ctx) {
		return app.fetch(request, env, ctx)
	},
	async scheduled(event, env, ctx) {
		ctx.waitUntil(cacheRoles(event, env));
	}
  };
  