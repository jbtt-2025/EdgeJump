// SSH 2.0 Transport and Identification for EdgeJump

// RFC 4253 exchange hashes use this exact line without its CRLF terminator.
export const SSH_VERSION = 'SSH-2.0-EdgeJump_1.0';

export function isSSH2Identification(value: string): boolean {
  return value.startsWith('SSH-2.0-') || value.startsWith('SSH-1.99-');
}

export class SSHTransport {
  private remoteVersion: string = '';
  private readonly localVersion: string = SSH_VERSION;

  setRemoteVersion(version: string): void {
    this.remoteVersion = version;
  }

  getRemoteVersion(): string {
    return this.remoteVersion;
  }

  getLocalVersion(): string {
    return this.localVersion;
  }

  getLocalIdentification(): Uint8Array {
    return new TextEncoder().encode(`${this.localVersion}\r\n`);
  }

  /**
   * Search an incoming buffer for the server's SSH-2.0 identification line (RFC 4253 Section 4.2).
   * Servers may send lines of text before the identification banner.
   */
  static parseIdentification(buffer: Uint8Array): { version: string; consumed: number } | null {
    const text = new TextDecoder('utf-8').decode(buffer);
    const lines = text.split(/\r?\n/);
    let consumed = 0;

    for (let i = 0; i < lines.length - 1; i++) {
      const line = lines[i];
      // Account for the line and its newline in consumed bytes
      // Find the newline delimiter in original buffer
      const lineBytes = new TextEncoder().encode(line).length;
      // Look ahead in buffer to find exact line termination (CRLF or LF)
      let termLen = 1;
      if (consumed + lineBytes + 1 < buffer.length && buffer[consumed + lineBytes] === 0x0d && buffer[consumed + lineBytes + 1] === 0x0a) {
        termLen = 2;
      }
      consumed += lineBytes + termLen;

      if (isSSH2Identification(line)) {
        return {
          version: line,
          consumed,
        };
      }
    }

    return null;
  }
}
