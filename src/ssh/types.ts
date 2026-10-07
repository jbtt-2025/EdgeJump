// SSH 2.0 Protocol Types and Constants for EdgeJump

// SSH Message Numbers (RFC 4250 / RFC 4253 / RFC 4252 / RFC 4254)
export const SSH_MSG_DISCONNECT = 1;
export const SSH_MSG_IGNORE = 2;
export const SSH_MSG_UNIMPLEMENTED = 3;
export const SSH_MSG_DEBUG = 4;
export const SSH_MSG_SERVICE_REQUEST = 5;
export const SSH_MSG_SERVICE_ACCEPT = 6;
export const SSH_MSG_EXT_INFO = 7;
export const SSH_MSG_KEXINIT = 20;
export const SSH_MSG_NEWKEYS = 21;
export const SSH_MSG_KEX_ECDH_INIT = 30;
export const SSH_MSG_KEX_ECDH_REPLY = 31;
export const SSH_MSG_USERAUTH_REQUEST = 50;
export const SSH_MSG_USERAUTH_FAILURE = 51;
export const SSH_MSG_USERAUTH_SUCCESS = 52;
export const SSH_MSG_USERAUTH_INFO_REQUEST = 60;
export const SSH_MSG_USERAUTH_INFO_RESPONSE = 61;
export const SSH_MSG_GLOBAL_REQUEST = 80;
export const SSH_MSG_REQUEST_SUCCESS = 81;
export const SSH_MSG_REQUEST_FAILURE = 82;
export const SSH_MSG_CHANNEL_OPEN = 90;
export const SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
export const SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
export const SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
export const SSH_MSG_CHANNEL_DATA = 94;
export const SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
export const SSH_MSG_CHANNEL_EOF = 96;
export const SSH_MSG_CHANNEL_CLOSE = 97;
export const SSH_MSG_CHANNEL_REQUEST = 98;
export const SSH_MSG_CHANNEL_SUCCESS = 99;
export const SSH_MSG_CHANNEL_FAILURE = 100;

// Key Exchange Algorithms
export const KEX_ALGORITHM_CURVE25519_SHA256 = 'curve25519-sha256';
export const KEX_ALGORITHM_ECDH_NISTP256 = 'ecdh-sha2-nistp256';

export const SUPPORTED_KEX_ALGORITHMS = [
  KEX_ALGORITHM_CURVE25519_SHA256,
  KEX_ALGORITHM_ECDH_NISTP256,
] as const;

// Host Key Algorithms
export const SUPPORTED_HOST_KEY_ALGORITHMS = [
  'ssh-ed25519',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'rsa-sha2-512',
  'rsa-sha2-256',
] as const;

// Encryption Ciphers
export const SUPPORTED_ENCRYPTION_ALGORITHMS = [
  'aes128-gcm@openssh.com',
  'aes256-gcm@openssh.com',
  'aes128-ctr',
  'aes192-ctr',
  'aes256-ctr',
] as const;

// MAC Algorithms
export const SUPPORTED_MAC_ALGORITHMS = [
  'hmac-sha2-256',
  'hmac-sha2-512',
] as const;

export interface CipherSpec {
  mode: 'gcm' | 'ctr';
  blockSize: number;
  ivLength: number;
  keyLength: number;
  aead: boolean;
}

export interface MacSpec {
  length: number;
  keyLength: number;
}

const CIPHER_SPECS: Record<string, CipherSpec> = {
  'aes256-gcm@openssh.com': { mode: 'gcm', blockSize: 16, ivLength: 12, keyLength: 32, aead: true },
  'aes128-gcm@openssh.com': { mode: 'gcm', blockSize: 16, ivLength: 12, keyLength: 16, aead: true },
  'aes256-ctr': { mode: 'ctr', blockSize: 16, ivLength: 16, keyLength: 32, aead: false },
  'aes192-ctr': { mode: 'ctr', blockSize: 16, ivLength: 16, keyLength: 24, aead: false },
  'aes128-ctr': { mode: 'ctr', blockSize: 16, ivLength: 16, keyLength: 16, aead: false },
};

const MAC_SPECS: Record<string, MacSpec> = {
  none: { length: 0, keyLength: 32 },
  'hmac-sha2-256': { length: 32, keyLength: 32 },
  'hmac-sha2-512': { length: 64, keyLength: 64 },
};

export function isCurve25519KEXAlgorithm(algorithm: string): boolean {
  return algorithm === KEX_ALGORITHM_CURVE25519_SHA256;
}

export function getCipherSpec(algorithm: string): CipherSpec {
  const spec = CIPHER_SPECS[algorithm];
  if (!spec) throw new Error(`Unsupported cipher: ${algorithm}`);
  return spec;
}

export function getMacSpec(algorithm: string): MacSpec {
  const spec = MAC_SPECS[algorithm];
  if (!spec) throw new Error(`Unsupported MAC algorithm: ${algorithm}`);
  return spec;
}

export interface SSHPacket {
  length: number;
  paddingLength: number;
  payload: Uint8Array;
  mac?: Uint8Array;
}

export interface KEXInitMessage {
  kexAlgorithms: string[];
  hostKeyAlgorithms: string[];
  encryptionC2S: string[];
  encryptionS2C: string[];
  macC2S: string[];
  macS2C: string[];
  compressionC2S: string[];
  compressionS2C: string[];
  firstKexPacketFollows: boolean;
}

export interface SessionKeys {
  ivClientToServer: Uint8Array;
  ivServerToClient: Uint8Array;
  encKeyClientToServer: Uint8Array;
  encKeyServerToClient: Uint8Array;
  integrityKeyC2S: Uint8Array;
  integrityKeyS2C: Uint8Array;
  sessionID: Uint8Array;
}

export interface TerminalSize {
  cols: number;
  rows: number;
}

export function normalizeTerminalSize(cols: unknown, rows: unknown): TerminalSize | null {
  if (typeof cols !== 'number' || typeof rows !== 'number' || !Number.isFinite(cols) || !Number.isFinite(rows)) {
    return null;
  }
  const size = { cols: Math.floor(cols), rows: Math.floor(rows) };
  return size.cols >= 10 && size.cols <= 1000 && size.rows >= 5 && size.rows <= 1000 ? size : null;
}

export interface SSHConnectionConfig {
  type: 'connect';
  host: string;
  port: number;
  username: string;
  authMethod: 'password' | 'publickey';
  password?: string;
  privateKey?: string;
  cols: number;
  rows: number;
  term: string;
  expectedFingerprint?: string;
}

export type HostKeyTrust = 'trusted' | 'first-seen' | 'changed';
