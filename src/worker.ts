import type { Env } from './types.ts';
import { SSHSessionDO } from './durable/SSHSessionDO.ts';
import { RateLimitDO } from './durable/RateLimitDO.ts';
import { PasswordKdfDO } from './durable/PasswordKdfDO.ts';
import { PasswordKdfUnavailableError } from './auth/password-service.ts';
import { handleApiRequest } from './api/router.ts';
import { isProductionHttp, httpsRedirect, secureHeaders } from './http-security.ts';

import { cleanupExpiredRecordings } from './sessions/cleanup-service.ts';
import { logError } from './logging.ts';

// Export Durable Objects required by wrangler.toml
export { SSHSessionDO, RateLimitDO, PasswordKdfDO };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Enforce HTTPS in production environments
    if (isProductionHttp(request)) {
      if (request.method === 'GET' || request.method === 'HEAD') {
        return httpsRedirect(request);
      }
      return secureHeaders(new Response('HTTPS is required', { status: 403 }));
    }

    // Health check endpoint
    if (url.pathname === '/api/health') {
      return secureHeaders(
        Response.json({
          status: 'ok',
          service: 'EdgeJump Bastion',
          runtime: 'cloudflare-workers',
          version: '1.0.0',
          deployType: env.DEPLOY_TYPE || 'production',
        })
      );
    }

    // API Routing
    if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
      try {
        return await handleApiRequest(request, env);
      } catch (error) {
        if (error instanceof PasswordKdfUnavailableError) return secureHeaders(Response.json({ error: error.message }, { status: 503 }));
        logError('api_request_failed', error);
        return secureHeaders(Response.json({ error: 'Request could not be completed' }, { status: 400 }));
      }
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

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(cleanupExpiredRecordings(env, 'cron'));
  },
};
