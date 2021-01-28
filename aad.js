import cookie from 'cookie'
import { getDecryptedKV, putEncryptedKV } from 'encrypt-workers-kv'

const password = PASSWORD // workers secret
const sessionDuration = 86400

const aad = {
  domain: AAD_DOMAIN,
  clientId: AAD_CLIENT_ID,
  clientSecret: AAD_CLIENT_SECRET,
  callbackUrl: AAD_CALLBACK_URL,
}

const cookieKey = 'AAD-AUTH'

const csprng = () =>
  btoa(
    String.fromCharCode.apply(null, crypto.getRandomValues(new Uint8Array(32))),
  )

const generateStateParam = async () => {
  const state = csprng()
  await AUTH_STORE.put(`state-${state}`, true, {
    expirationTtl: sessionDuration,
  })
  return state
}

const exchangeCode = async code => {
  const body = `client_id=${aad.clientId}&scope=openid%20profile%20email&code=${code}&redirect_uri=${aad.callbackUrl}&grant_type=authorization_code&client_secret=${aad.clientSecret}`

  return persistAuth(
    await fetch(`${aad.domain}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    }),
  )
}

// https://github.com/pose/webcrypto-jwt/blob/master/index.js
const decodeJWT = function(token) {
  var output = token
    .split('.')[1]
    .replace(/-/g, '+')
    .replace(/_/g, '/')
  switch (output.length % 4) {
    case 0:
      break
    case 2:
      output += '=='
      break
    case 3:
      output += '='
      break
    default:
      throw 'Illegal base64url string!'
  }

  const result = atob(output)

  try {
    return decodeURIComponent(escape(result))
  } catch (err) {
    console.log(err)
    return result
  }
}

/**
 * Parse and decode a JWT.
 * A JWT is three, base64 encoded, strings concatenated with ‘.’:
 *   a header, a payload, and the signature.
 * The signature is “URL safe”, in that ‘/+’ characters have been replaced by ‘_-’
 * 
 * Steps:
 * 1. Split the token at the ‘.’ character
 * 2. Base64 decode the individual parts
 * 3. Retain the raw Bas64 encoded strings to verify the signature
 * Src: https://gist.github.com/bcnzer/e6a7265fd368fa22ef960b17b9a76488
 */
function decodeFullJWT(token) {
  const parts = token.split('.');
  const header = JSON.parse(atob(parts[0]));
  const payload = JSON.parse(atob(parts[1]));
  const signature = atob(parts[2].replace(/_/g, '/').replace(/-/g, '+'));

  return {
    header: header,
    payload: payload,
    signature: signature,
    raw: { header: parts[0], payload: parts[1], signature: parts[2] }
  }
}

/**
 * Validate the JWT.
 *
 * Steps:
 * Reconstruct the signed message from the Base64 encoded strings.
 * Load the RSA public key into the crypto library.
 * Verify the signature with the message and the key.
 * Src: https://gist.github.com/bcnzer/e6a7265fd368fa22ef960b17b9a76488
 */
async function isValidJwtSignature(token) {
  const encoder = new TextEncoder();
  const data = encoder.encode([token.raw.header, token.raw.payload].join('.'));
  const signature = new Uint8Array(Array.from(token.signature).map(c => c.charCodeAt(0)));

  const keysData = await fetch("https://login.microsoftonline.com/common/discovery/v2.0/keys")
    .then(response => response.json())

  const kid = token.header.kid
  const key = keysData.keys.filter((k) => k.kid === kid).shift()

  const jwk = {
    alg: "RS256",
    kty: key.kty,
    key_ops: ['verify'],
    use: "sig",
    x5c: key.x5c,
    n: key.n,
    e: key.e,
    kid: key.kid,
    x5t: key.x5t
    }

  const validationKey = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  return crypto.subtle.verify('RSASSA-PKCS1-v1_5', validationKey, signature, data)

}

const validateToken = async token => {
  try {
    const dateInSecs = d => Math.ceil(Number(d) / 1000)
    const date = new Date()

    let iss = token.iss

    // ISS can include a trailing slash but should otherwise be identical to
    // the aad.domain, so we should remove the trailing slash if it exists
    iss = iss.endsWith('/') ? iss.slice(0, -1) : iss

    if (iss !== `${aad.domain}/v2.0`) {
      throw new Error(
        `Token iss value (${iss}) doesn't match aad.domain (${aad.domain})`,
      )
    }

    if (token.aud !== aad.clientId) {
      throw new Error(
        `Token aud value (${token.aud}) doesn't match aad.clientId (${aad.clientId})`,
      )
    }

    if (token.exp < dateInSecs(date)) {
      throw new Error(`Token exp value is before current time`)
    }

    // Token should have been issued within the last day
    date.setDate(date.getDate() - 1)
    if (token.iat < dateInSecs(date)) {
      throw new Error(`Token was issued before one day ago and is now invalid`)
    }

    return true
  } catch (err) {
    console.log(err.message)
    return false
  }
}

const persistAuth = async exchange => {
  const body = await exchange.json()

  if (body.error) {
    throw new Error(body.error)
  }

  const date = new Date()
  date.setDate(date.getDate() + 1)

  const token = decodeFullJWT(body.id_token)
  const validToken = await validateToken(token.payload)
  const validSig = await isValidJwtSignature(token)

  if (!validToken || !validSig) {
    console.log('invalid token')
    return { status: 401 }
  }

  const salt = crypto.getRandomValues(new Uint8Array(16))
  const text = new TextEncoder().encode(`${salt}-${token.payload.sub}`)
  const digest = await crypto.subtle.digest({ name: 'SHA-256' }, text)
  const digestArray = new Uint8Array(digest)
  const id = btoa(String.fromCharCode.apply(null, digestArray))

  await putEncryptedKV(AUTH_STORE, id, JSON.stringify(body), password, 10000, {
    expirationTtl: sessionDuration,
  })

  const headers = {
    Location: '/',
    'Set-cookie': `${cookieKey}=${id}; Secure; HttpOnly; SameSite=Lax; Max-Age=${sessionDuration}`,
  }

  return { headers, status: 302 }
}

const redirectUrl = state =>
  `${aad.domain}/oauth2/v2.0/authorize?client_id=${
    aad.clientId
  }&response_type=code&redirect_uri=${
    aad.callbackUrl
  }&response_mode=query&scope=openid%20profile%20email&state=${encodeURIComponent(
    state,
  )}`

export const handleRedirect = async event => {
  const url = new URL(event.request.url)

  const state = url.searchParams.get('state')
  if (!state) {
    return null
  }

  const storedState = await AUTH_STORE.get(`state-${state}`)
  if (!storedState) {
    return null
  }

  const code = url.searchParams.get('code')
  if (code) {
    return exchangeCode(code)
  }

  return null
}

const verify = async event => {
  const cookieHeader = event.request.headers.get('Cookie')
  if (cookieHeader && cookieHeader.includes(cookieKey)) {
    const cookies = cookie.parse(cookieHeader)
    if (!cookies[cookieKey]) return {}
    const sub = cookies[cookieKey]
    let session

    try {
      session = await getDecryptedKV(AUTH_STORE, sub, password)
    } catch (e) {
      return {}
    }

    const kvData = new TextDecoder().decode(session)

    let kvStored
    try {
      kvStored = JSON.parse(kvData)
    } catch (err) {
      throw new Error('Unable to parse auth information from Workers KV')
    }

    const { access_token: accessToken, id_token: idToken } = kvStored
    const userInfo = JSON.parse(decodeJWT(idToken))
    return { accessToken, idToken, userInfo }
  }
  return {}
}

export const authorize = async event => {
  const authorization = await verify(event)
  if (authorization.accessToken) {
    return [true, { authorization }]
  } else {
    const state = await generateStateParam()
    console.log(`Generated state param for ${event.request.url}`)
    return [false, { redirectUrl: redirectUrl(state) }]
  }
}

export const logout = event => {
  const cookieHeader = event.request.headers.get('Cookie')
  if (cookieHeader && cookieHeader.includes(cookieKey)) {
    return {
      headers: {
        'Set-cookie': `${cookieKey}=""; HttpOnly; Secure; SameSite=Lax;`,
      },
    }
  }
  return {}
}
