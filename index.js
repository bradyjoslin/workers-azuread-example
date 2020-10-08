import { getAssetFromKV } from '@cloudflare/kv-asset-handler'

import { authorize, logout, handleRedirect } from './aad'
import { hydrateState } from './edge_state'

addEventListener('fetch', event => event.respondWith(handleRequest(event)))

// see the readme for more info on what these config options do!
const config = {
  // opt into automatic authorization state hydration
  hydrateState: true,
  // return responses at the edge
  originless: true,
}

async function handleRequest(event) {
  try {
    let request = event.request

    let response = config.originless
      ? new Response(null)
      : await fetch(event.request)

    const url = new URL(event.request.url)
    const [authorized, { authorization, redirectUrl }] =
      url.pathname !== '/favicon.ico' && url.pathname !== '/auth'
        ? await authorize(event)
        : [false, {}]

    if (authorized && authorization.accessToken) {
      request = new Request(request, {
        headers: {
          Authorization: `Bearer ${authorization.accessToken}`,
        },
      })
    }

    if (url.pathname === '/auth') {
      const authorizedResponse = await handleRedirect(event)
      if (!authorizedResponse) {
        return new Response('Unauthorized', { status: 401 })
      }
      response = new Response(response.body, {
        response,
        ...authorizedResponse,
      })
      return response
    }

    if (!authorized && redirectUrl) {
      return Response.redirect(redirectUrl)
    }

    response = await getAssetFromKV(event)

    if (url.pathname === '/logout') {
      const { headers } = logout(event)
      return headers
        ? new Response(response.body, {
            ...response,
            headers: Object.assign({}, response.headers, headers),
          })
        : Response.redirect(url.origin)
    }

    // hydrate the static site with authorization info from auth0
    // this uses alpine.js and the htmlrewriter engine built into
    // workers. for more info, check out the README
    return config.hydrateState
      ? new HTMLRewriter()
          .on('script#edge_state', hydrateState(authorization.userInfo))
          .transform(response)
      : response
  } catch (err) {
    return new Response('', { status: 404 })
  }
}
