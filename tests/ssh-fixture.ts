import ssh2, { type Connection, type ServerChannel } from 'ssh2';
import { generateKeyPairSync } from 'node:crypto';
import net from 'node:net';
import { Readable, Writable } from 'node:stream';
import { createContext, seedDemoTopology, type ComplianceContext } from './compliance-helpers.ts';
import { setCustomSocketConnector } from '../src/durable/SSHSessionDO.ts';
import { createCredential } from '../src/credentials/credential-service.ts';
import { updateAssetAccount } from '../src/assets/asset-service.ts';

export const SSH_PASSWORD = 'fixture-ssh-password';
const hostKey = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs1', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey;
export const CLIENT_PRIVATE_KEY = ssh2.utils.generateKeyPairSync('ed25519').private;
const clientKey = ssh2.utils.parseKey(CLIENT_PRIVATE_KEY);

export async function createSshFixture(options: { password?: string; storage?: boolean; hang?: boolean; malformed?: boolean; hostKey?: string } = {}) {
  const ctx = await createContext();
  const topo = await seedDemoTopology(ctx, 'fixture-private-key-placeholder');
  const credential = await createCredential({ name: 'integration-password', type: 'password', secret: options.password ?? SSH_PASSWORD }, ctx.kek, ctx.db);
  await updateAssetAccount(topo.deploy.id, { credentialId: credential.id }, ctx.db);
  return { ...await startSshServer(ctx, options), topo };
}

export async function startSshServer(ctx: ComplianceContext, options: { storage?: boolean; hang?: boolean; malformed?: boolean; hostKey?: string } = {}) {
  const objects = new Map<string, Uint8Array>();
  if (options.storage !== false) ctx.env.RECORDINGS = {
    async put(key: string, value: string | Uint8Array) { objects.set(key, typeof value === 'string' ? new TextEncoder().encode(value) : value.slice()); },
    async get(key: string) {
      const bytes = objects.get(key); if (!bytes) return null;
      return { arrayBuffer: async () => bytes.slice().buffer, text: async () => new TextDecoder().decode(bytes), json: async () => JSON.parse(new TextDecoder().decode(bytes)) };
    },
    async delete(key: string) { objects.delete(key); },
  } as unknown as R2Bucket;
  const sizes: { cols: number; rows: number }[] = [];
  const input: string[] = [];
  const peers = new Set<Connection>();
  const channels = new Set<ServerChannel>();
  const sshServer = new ssh2.Server({ hostKeys: [options.hostKey ?? hostKey] }, (client) => {
    peers.add(client); client.on('error', () => {}); client.on('close', () => peers.delete(client));
    client.on('authentication', (auth) => {
      if (auth.method === 'publickey' && !(clientKey instanceof Error) && auth.key.data.length === clientKey.getPublicSSH().length && auth.key.data.every((byte, index) => byte === clientKey.getPublicSSH()[index]) && (!auth.signature || clientKey.verify(auth.blob!, auth.signature, auth.hashAlgo) === true)) auth.accept();
      else if (auth.method === 'password' && auth.username === 'deploy' && auth.password === SSH_PASSWORD) auth.accept();
      else auth.reject();
    });
    client.on('ready', () => client.on('session', (accept) => {
      const session = accept();
      session.on('pty', (accept, _reject, info) => { sizes.push({ cols: info.cols, rows: info.rows }); accept?.(); });
      session.on('window-change', (_accept, _reject, info) => { sizes.push({ cols: info.cols, rows: info.rows }); });
      session.on('shell', (accept) => {
        const channel = accept(); channels.add(channel);
        channel.on('close', () => channels.delete(channel));
        channel.write('Welcome to EdgeJump test SSH\r\n$ ');
        let line = '';
        channel.on('data', (data: Buffer) => {
          const text = data.toString(); input.push(text); line += text; channel.write(text.replace(/\r/g, '\r\n'));
          while (line.includes('\r') || line.includes('\n')) {
            const match = /\r\n|\r|\n/.exec(line)!;
            const command = line.slice(0, match.index); line = line.slice(match.index + match[0].length);
            if (command === 'exit') { channel.exit(7); channel.end('Goodbye\r\n'); }
            else channel.write(`executed: ${command}\r\n$ `);
          }
        });
      });
    }));
  });
  await new Promise<void>((resolve, reject) => { sshServer.once('error', reject); sshServer.listen(0, '127.0.0.1', resolve); });
  const address = sshServer.address() as net.AddressInfo;
  const connections: string[] = [];
  setCustomSocketConnector(async (target) => {
    connections.push(`${target.hostname}:${target.port}`);
    if (target.hostname !== '8.8.8.8') throw new Error('Unexpected integration target');
    if (options.hang || options.malformed) {
      let reader: ReadableStreamDefaultController<Uint8Array>;
      let closed = false;
      return { readable: new ReadableStream<Uint8Array>({ start(controller) { reader = controller; if (options.malformed) { controller.enqueue(new TextEncoder().encode('SSH-2.0-invalid\r\n')); controller.enqueue(new Uint8Array([255, 255, 255, 255, 0, 0, 0, 0])); } } }), writable: new WritableStream(), close() { if (!closed) { closed = true; reader.close(); } } };
    }
    const socket = net.connect(address.port, '127.0.0.1');
    await new Promise<void>((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    return { readable: Readable.toWeb(socket) as ReadableStream<Uint8Array>, writable: Writable.toWeb(socket) as WritableStream<Uint8Array>, close() { socket.destroy(); } };
  });
  return { ctx, sizes, input, connections, objects, channels,
    async close() { await ctx.cleanup(); for (const peer of peers) peer.end(); await new Promise<void>((resolve) => sshServer.close(() => resolve())); },
  };
}

export async function eventually(predicate: () => boolean | Promise<boolean>, label: string, timeout = 5000) {
  const deadline = Date.now() + timeout;
  while (!await predicate()) {
    if (Date.now() > deadline) throw new Error(`Timed out: ${label}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}
