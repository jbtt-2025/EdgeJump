import { PasswordKdfDO } from '../src/durable/PasswordKdfDO.ts';
import type { Env } from '../src/types.ts';

/** Exercises the real internal handler without Cloudflare networking. */
export function createPasswordKdfNamespace(pepper = ''): DurableObjectNamespace {
  const instance = new PasswordKdfDO({} as DurableObjectState, { AUTH_PEPPER: pepper } as Env);
  return {
    idFromName: (name: string) => name,
    get: () => ({ fetch: (input: RequestInfo, init?: RequestInit) => instance.fetch(new Request(input, init)) }),
  } as unknown as DurableObjectNamespace;
}
