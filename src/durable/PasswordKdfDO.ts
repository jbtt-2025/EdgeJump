import type { Env } from '../types.ts';
import { hashPassword, verifyPassword } from '../crypto/password.ts';

/** Internal, stateless password computation. No storage, sockets, timers or public routes. */
export class PasswordKdfDO {
  private readonly pepper: string;

  constructor(_state: DurableObjectState, env: Env) {
    this.pepper = env.AUTH_PEPPER || '';
  }

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (request.method !== 'POST' || !['/hash', '/verify'].includes(path)) return new Response(null, { status: 404 });
    try {
      const body = await request.json<{ password: string; hash: string; salt: string; iterations: number }>();
      if (typeof body.password !== 'string') return new Response(null, { status: 400 });
      if (path === '/hash') return Response.json(await hashPassword(body.password, this.pepper));
      if (typeof body.hash !== 'string' || typeof body.salt !== 'string' || !Number.isSafeInteger(body.iterations) || body.iterations < 1) {
        return new Response(null, { status: 400 });
      }
      return Response.json({ valid: await verifyPassword(body.password, this.pepper, body.hash, body.salt, body.iterations) });
    } catch {
      // Never include input material or runtime exception text in responses/logs.
      return Response.json({ error: 'Password service unavailable' }, { status: 503 });
    }
  }
}
