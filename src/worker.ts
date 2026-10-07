import type { Env } from './types.ts';
import { SSHSessionDO } from './durable/SSHSessionDO.ts';
import { RateLimitDO } from './durable/RateLimitDO.ts';
import { handleApiRequest } from './api/router.ts';
import { isProductionHttp, httpsRedirect, secureHeaders } from './http-security.ts';

// Export Durable Objects required by wrangler.toml
export { SSHSessionDO, RateLimitDO };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Enforce HTTPS in production environments
    if (isProductionHttp(request)) {
      if (request.method === 'GET' || request.method === 'HEAD') {
        return httpsRedirect(request);
      }
      return new Response('HTTPS is required', { status: 403 });
    }

    // Health check endpoint
    if (url.pathname === '/api/health') {
      return secureHeaders(
        Response.json({
          status: 'ok',
          service: 'EdgeJump Bastion',
          runtime: 'cloudflare-workers',
          version: '1.0.0',
        })
      );
    }

    // API Routing
    if (url.pathname.startsWith('/api/')) {
      return handleApiRequest(request, env);
    }

    // Static Asset Serving (Frontend Single-Page Application)
    if (env.ASSETS) {
      const assetResponse = await env.ASSETS.fetch(request);
      return secureHeaders(assetResponse);
    }

    return new Response('EdgeJump Bastion Worker Ready', {
      headers: { 'Content-Type': 'text/plain' },
    });
  },
};
