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
  private cursor = 0;
  private uncertain = false;
  private escape = '';
  private promptTail = '';
  private inputDecoder = new TextDecoder();
  private pending: Promise<void> = Promise.resolve();
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
    this.promptTail = (this.promptTail + text).slice(-512);
    const cleaned = this.promptTail.replace(ANSI_ESCAPE_REGEX, '').trimEnd();

    if (SENSITIVE_PROMPT_REGEX.test(cleaned)) {
      this.isSensitivePrompt = true;
    }
  }

  /** Reconstruct edits we can observe; history/completion remains explicitly uncertain. */
  feedStdin(chunk: string | Uint8Array): HeuristicCommand[] {
    const text = typeof chunk === 'string' ? chunk : this.inputDecoder.decode(chunk, { stream: true });
    const submitted: HeuristicCommand[] = [];
    for (const char of text) {
      if (this.escape) {
        this.escape += char;
        if (this.escape === '\x1b[' || this.escape === '\x1bO') continue;
        if (/^\x1b(?:\[[0-9;?]*|O)[A-Za-z~]$/.test(this.escape)) {
          this.editEscape(this.escape);
          this.escape = '';
        } else if (this.escape.length > 20 || !/^\x1b(?:\[[0-9;?]*|O)?$/.test(this.escape)) {
          this.uncertain = true;
          this.escape = '';
        }
        continue;
      }
      if (char === '\x1b') { this.escape = char; continue; }
      if (char === '\r' || char === '\n') {
        if (char === '\n' && this.lastCharWasCarriageReturn) { this.lastCharWasCarriageReturn = false; continue; }
        this.lastCharWasCarriageReturn = char === '\r';
        const entry = this.submitLine();
        if (entry) submitted.push(entry);
        continue;
      }
      this.lastCharWasCarriageReturn = false;
      if (char === '\x03' || char === '\x15') {
        if (char === '\x03') { this.lineBuffer = ''; this.cursor = 0; this.uncertain = false; this.isSensitivePrompt = false; }
        else { this.lineBuffer = this.lineBuffer.slice(this.cursor); this.cursor = 0; }
        continue;
      }
      if (char === '\x01') { this.cursor = 0; continue; }
      if (char === '\x05') { this.cursor = this.lineBuffer.length; continue; }
      if (char === '\t') { this.uncertain = true; continue; }
      if (char === '\x7f' || char === '\b') {
        if (this.cursor > 0) {
          const previous = Array.from(this.lineBuffer.slice(0, this.cursor)).at(-1)!;
          this.lineBuffer = this.lineBuffer.slice(0, this.cursor - previous.length) + this.lineBuffer.slice(this.cursor);
          this.cursor -= previous.length;
        }
        continue;
      }
      if (char.charCodeAt(0) >= 32) {
        this.lineBuffer = this.lineBuffer.slice(0, this.cursor) + char + this.lineBuffer.slice(this.cursor);
        this.cursor += char.length;
        if (this.lineBuffer.length > 4096) { this.lineBuffer = ''; this.cursor = 0; this.uncertain = true; }
      }
    }
    return submitted;
  }

  private editEscape(sequence: string): void {
    const key = sequence.at(-1);
    const count = Math.max(1, Number(sequence.slice(2, -1).split(';')[0]) || 1);
    if (key === 'D') {
      for (let n = 0; n < Math.min(count, 4096) && this.cursor > 0; n++) this.cursor -= Array.from(this.lineBuffer.slice(0, this.cursor)).at(-1)!.length;
    } else if (key === 'C') {
      for (let n = 0; n < Math.min(count, 4096) && this.cursor < this.lineBuffer.length; n++) this.cursor += Array.from(this.lineBuffer.slice(this.cursor))[0].length;
    } else if (key === 'H' || sequence === '\x1b[1~') this.cursor = 0;
    else if (key === 'F' || sequence === '\x1b[4~') this.cursor = this.lineBuffer.length;
    else if (sequence === '\x1b[3~') this.lineBuffer = this.lineBuffer.slice(0, this.cursor) + Array.from(this.lineBuffer.slice(this.cursor)).slice(1).join('');
    else this.uncertain = true;
  }

  private submitLine(): HeuristicCommand | null {
    const raw = this.lineBuffer.trim();
    const sensitive = this.isSensitivePrompt;
    const uncertain = this.uncertain;
    this.lineBuffer = ''; this.cursor = 0; this.uncertain = false; this.isSensitivePrompt = false; this.promptTail = '';
    if (!raw && !uncertain && !sensitive) return null;
    const now = Date.now();
    const entry: HeuristicCommand = {
      id: crypto.randomUUID(), sessionId: this.sessionId, timestamp: now,
      command: sensitive ? '[REDACTED]' : uncertain ? '[UNCERTAIN]' : raw,
      source: 'heuristic', redacted: sensitive ? 1 : 0, createdAt: now,
    };
    this.recordedCommands.push(entry);
    if (this.recordedCommands.length > 200) this.recordedCommands.shift();
    if (this.d1Database) this.pending = this.pending.then(() => this.persistCommand(entry));
    return entry;
  }

  async flush(): Promise<void> { await this.pending; }

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
