// Terminal Command Reconstruction and Sensitive Prompt Redaction Heuristics for EdgeJump

export interface HeuristicCommand {
  id: string;
  sessionId: string;
  timestamp: number;
  command: string;
  source: 'heuristic';
  redacted: number;
  createdAt: number;
}

const SENSITIVE_PROMPT_REGEX = /(?:password|passphrase|token|verification\s*code|pin|secret)(?:[^\n\r]*[:?])?\s*$/i;
const ANSI_ESCAPE_REGEX = /\x1b\[[0-9;?]*[a-zA-Z~]/g;

export class CommandHeuristicsTracker {
  private readonly sessionId: string;
  private readonly d1Database?: D1Database;
  private lineBuffer: string = '';
  private isSensitivePrompt: boolean = false;
  private lastCharWasCarriageReturn: boolean = false;
  private readonly recordedCommands: HeuristicCommand[] = [];

  constructor(sessionId: string, d1Database?: D1Database) {
    this.sessionId = sessionId;
    this.d1Database = d1Database;
  }

  getRecordedCommands(): readonly HeuristicCommand[] {
    return this.recordedCommands;
  }

  getCurrentLineBuffer(): string {
    return this.lineBuffer;
  }

  isPromptSensitive(): boolean {
    return this.isSensitivePrompt;
  }

  /**
   * Examines terminal stdout to detect sensitive password/token prompts.
   */
  feedStdout(chunk: string | Uint8Array): void {
    const text = typeof chunk === 'string' ? chunk : new TextDecoder().decode(chunk);
    const cleaned = text.replace(ANSI_ESCAPE_REGEX, '').trimEnd();

    if (SENSITIVE_PROMPT_REGEX.test(cleaned)) {
      this.isSensitivePrompt = true;
    }
  }

  /**
   * Processes user stdin characters, reconstructing commands across Enter, Backspace, Ctrl+C, Ctrl+U.
   * Returns newly submitted command entry if Enter was pressed with non-empty content.
   */
  feedStdin(chunk: string | Uint8Array): HeuristicCommand[] {
    const text = typeof chunk === 'string' ? chunk : new TextDecoder().decode(chunk);
    const newCommands: HeuristicCommand[] = [];

    // Filter out multi-character terminal control sequences like arrow keys \x1b[A
    const sanitized = text.replace(ANSI_ESCAPE_REGEX, '');

    for (let i = 0; i < sanitized.length; i++) {
      const char = sanitized[i];
      const code = char.charCodeAt(0);

      // Handle Enter (\r or \n)
      if (char === '\r' || char === '\n') {
        // Prevent double submit on \r\n
        if (char === '\n' && this.lastCharWasCarriageReturn) {
          this.lastCharWasCarriageReturn = false;
          continue;
        }
        this.lastCharWasCarriageReturn = (char === '\r');

        const submitted = this.submitLine();
        if (submitted) {
          newCommands.push(submitted);
        }
        continue;
      }

      this.lastCharWasCarriageReturn = false;

      // Handle Backspace (DEL 0x7f or BS 0x08)
      if (code === 0x7f || code === 0x08) {
        if (this.lineBuffer.length > 0) {
          this.lineBuffer = this.lineBuffer.slice(0, -1);
        }
        continue;
      }

      // Handle Ctrl+C (0x03) - abort line
      if (code === 0x03) {
        this.lineBuffer = '';
        this.isSensitivePrompt = false;
        continue;
      }

      // Handle Ctrl+U (0x15) - clear line
      if (code === 0x15) {
        this.lineBuffer = '';
        continue;
      }

      // Handle regular printable characters (space and above)
      if (code >= 32 && code <= 126 || code > 127) {
        this.lineBuffer += char;
      }
    }

    return newCommands;
  }

  private submitLine(): HeuristicCommand | null {
    const raw = this.lineBuffer.trim();
    this.lineBuffer = '';

    if (raw.length === 0) {
      return null;
    }

    const isRedacted = this.isSensitivePrompt;
    this.isSensitivePrompt = false; // Reset sensitive prompt flag after line submission

    const commandText = isRedacted ? '[REDACTED]' : raw;
    const now = Date.now();

    const entry: HeuristicCommand = {
      id: crypto.randomUUID(),
      sessionId: this.sessionId,
      timestamp: now,
      command: commandText,
      source: 'heuristic',
      redacted: isRedacted ? 1 : 0,
      createdAt: now,
    };

    this.recordedCommands.push(entry);

    if (this.d1Database) {
      this.persistCommand(entry).catch((err) => {
        console.error(`[Heuristics] Failed to write command to D1 for session ${this.sessionId}:`, err);
      });
    }

    return entry;
  }

  private async persistCommand(entry: HeuristicCommand): Promise<void> {
    if (!this.d1Database) return;
    await this.d1Database
      .prepare(
        `INSERT INTO session_commands (id, session_id, timestamp, command, source, redacted, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        entry.id,
        entry.sessionId,
        entry.timestamp,
        entry.command,
        entry.source,
        entry.redacted,
        entry.createdAt
      )
      .run();
  }
}
