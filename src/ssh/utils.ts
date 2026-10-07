// SSH 2.0 Utility Helpers for EdgeJump

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

/** Workers WebCrypto currently types BufferSource as ArrayBuffer-backed only. */
export function toBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

export function concat(...arrays: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const arr of arrays) {
    totalLength += arr.length;
  }

  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

export function readUint32(data: Uint8Array, offset: number): number {
  return (
    (data[offset] << 24) |
    (data[offset + 1] << 16) |
    (data[offset + 2] << 8) |
    data[offset + 3]
  ) >>> 0;
}

export function writeUint32(data: Uint8Array, offset: number, value: number): void {
  data[offset] = (value >>> 24) & 0xff;
  data[offset + 1] = (value >>> 16) & 0xff;
  data[offset + 2] = (value >>> 8) & 0xff;
  data[offset + 3] = value & 0xff;
}

export function encodeUint32(value: number): Uint8Array {
  const buf = new Uint8Array(4);
  writeUint32(buf, 0, value);
  return buf;
}

export function encodeString(input: string | Uint8Array): Uint8Array {
  const encoded = typeof input === 'string'
    ? textEncoder.encode(input)
    : input;
  const result = new Uint8Array(4 + encoded.length);
  writeUint32(result, 0, encoded.length);
  result.set(encoded, 4);
  return result;
}

export function readBytes(bytes: Uint8Array, offset: number, label = 'SSH key data'): { value: Uint8Array; next: number } {
  if (offset + 4 > bytes.length) throw new Error(`Malformed ${label}`);
  const length = readUint32(bytes, offset);
  if (length > bytes.length - offset - 4) throw new Error(`Malformed ${label}`);
  return { value: bytes.subarray(offset + 4, offset + 4 + length), next: offset + 4 + length };
}

export function readString(bytes: Uint8Array, offset: number, label = 'SSH text field'): { value: string; next: number } {
  const field = readBytes(bytes, offset, label);
  try {
    return { value: textDecoder.decode(field.value), next: field.next };
  } catch {
    throw new Error(`Malformed ${label}: invalid UTF-8`);
  }
}

export function readSSHString(
  data: Uint8Array,
  offset: number,
  label = 'SSH data'
): { value: Uint8Array; offset: number } {
  if (offset + 4 > data.length) throw new Error(`Malformed ${label} length`);
  const length = readUint32(data, offset);
  offset += 4;
  if (offset + length > data.length) throw new Error(`Malformed ${label} data`);
  return { value: data.slice(offset, offset + length), offset: offset + length };
}

export function readPositiveMPInt(
  data: Uint8Array,
  offset: number,
  label = 'SSH MPINT'
): { value: Uint8Array; offset: number } {
  const field = readSSHString(data, offset, label);
  const value = field.value;
  if (value.length === 0 || (value[0] & 0x80) !== 0) {
    throw new Error(`Malformed ${label}: expected a positive MPINT`);
  }
  if (value[0] === 0) {
    if (value.length === 1 || (value[1] & 0x80) === 0) {
      throw new Error(`Malformed ${label}: non-canonical MPINT`);
    }
    return { value: value.slice(1), offset: field.offset };
  }
  return field;
}

export function toSSHMPInt(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  const significant = bytes.subarray(start);
  const needsLeadingZero = significant.length > 0 && (significant[0] & 0x80) !== 0;
  const valueOffset = needsLeadingZero ? 5 : 4;
  const result = new Uint8Array(valueOffset + significant.length);

  writeUint32(result, 0, significant.length + (needsLeadingZero ? 1 : 0));
  result.set(significant, valueOffset);

  return result;
}

/** RFC 8731 interprets the X25519 byte string as a network-order integer. */
export function x25519SecretToSSHMPInt(bytes: Uint8Array): Uint8Array {
  if (bytes.length !== 32) throw new Error(`X25519 shared secret must be 32 bytes, got ${bytes.length}`);
  return toSSHMPInt(bytes);
}

export function sshMPInt(value: Uint8Array): Uint8Array {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) {
    start++;
  }
  const significant = value.subarray(start);
  const needsLeadingZero = significant.length > 0 && (significant[0] & 0x80) !== 0;
  const data = needsLeadingZero
    ? concat(new Uint8Array([0]), significant)
    : significant;

  return encodeString(data);
}

export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('Invalid Base64URL value');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  if (toBase64Url(Uint8Array.from(binary, (char) => char.charCodeAt(0))) !== value) {
    throw new Error('Non-canonical Base64URL value');
  }
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function base64UrlUnsigned(bytes: Uint8Array): string {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  return toBase64(bytes.subarray(start)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}
