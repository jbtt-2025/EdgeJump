// Zmodem (lrzsz) Web Integration for EdgeJump Terminal
// Supports:
// 1. `sz <filename>` -> Server sends file to client (auto download)
// 2. `rz` -> Server requests file from client (file chooser upload)

// @ts-ignore - zmodem.js lacks standard type definitions
import Zmodem from 'zmodem.js/src/zmodem_browser.js';
import type { Terminal } from '@xterm/xterm';

export interface ZmodemSessionHandler {
  consume: (data: ArrayBuffer | Uint8Array) => void;
  hasActiveSession: () => boolean;
}

export function attachZmodem(
  term: Terminal,
  ws: WebSocket,
  onStatusChange?: (status: { active: boolean; type?: 'upload' | 'download'; fileName?: string; percent?: number }) => void
): ZmodemSessionHandler {
  let sentry: any;

  function senderFunc(octets: number[] | Uint8Array) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(new Uint8Array(octets));
    }
  }

  sentry = new Zmodem.Sentry({
    to_terminal(octets: number[] | Uint8Array) {
      term.write(new Uint8Array(octets));
    },
    sender: senderFunc,
    on_retract() {
      onStatusChange?.({ active: false });
    },
    on_detect(detection: any) {
      const session = detection.confirm();

      if (session.type === 'receive') {
        // Remote sent `sz <file>` (Download from remote server to browser)
        handleReceiveSession(session);
      } else if (session.type === 'send') {
        // Remote sent `rz` (Upload from browser to remote server)
        handleSendSession(session);
      }
    },
  });

  function handleReceiveSession(session: any) {
    onStatusChange?.({ active: true, type: 'download' });
    term.writeln('\r\n\x1b[36m[Zmodem]\x1b[0m 正在接收远端文件 (sz)...');

    session.on('offer', (xfer: any) => {
      const details = xfer.get_details();
      const fileName = details.name || 'download.bin';
      const totalSize = details.size || 0;
      let receivedBytes = 0;
      const chunks: Uint8Array[] = [];

      onStatusChange?.({ active: true, type: 'download', fileName, percent: 0 });

      xfer.on('input', (payload: Uint8Array) => {
        chunks.push(new Uint8Array(payload));
        receivedBytes += payload.length;
        if (totalSize > 0) {
          const percent = Math.round((receivedBytes / totalSize) * 100);
          onStatusChange?.({ active: true, type: 'download', fileName, percent });
        }
      });

      xfer.accept().then(() => {
        Zmodem.Browser.save_to_disk(chunks, fileName);
        term.writeln(`\r\n\x1b[32m[Zmodem]\x1b[0m 文件下载成功: \x1b[1m${fileName}\x1b[0m (${receivedBytes} bytes)`);
      }).catch((err: any) => {
        console.error('[Zmodem] Receive transfer error:', err);
        term.writeln(`\r\n\x1b[31m[Zmodem Error]\x1b[0m 下载失败: ${err.message || err}`);
      });
    });

    session.on('session_end', () => {
      onStatusChange?.({ active: false });
    });

    session.start();
  }

  function handleSendSession(session: any) {
    onStatusChange?.({ active: true, type: 'upload' });
    term.writeln('\r\n\x1b[36m[Zmodem]\x1b[0m 远端准备接收文件 (rz)，请选择本地文件...');

    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.multiple = true;
    fileInput.style.display = 'none';
    document.body.appendChild(fileInput);

    fileInput.onchange = () => {
      const files = fileInput.files;
      if (!files || files.length === 0) {
        term.writeln('\r\n\x1b[33m[Zmodem]\x1b[0m 用户取消了文件上传');
        session.close();
        document.body.removeChild(fileInput);
        onStatusChange?.({ active: false });
        return;
      }

      const fileList = Array.from(files);
      term.writeln(`\r\n\x1b[34m[Zmodem]\x1b[0m 开始上传 ${fileList.length} 个文件...`);

      Zmodem.Browser.send_files(session, fileList, {
        on_offer_response(file: File, xfer: any) {
          if (!xfer) {
            term.writeln(`\r\n\x1b[33m[Zmodem]\x1b[0m 远端拒绝接收文件: ${file.name}`);
          }
        },
        on_progress(file: File, xfer: any) {
          const percent = Math.round((xfer.get_offset() / file.size) * 100);
          onStatusChange?.({ active: true, type: 'upload', fileName: file.name, percent });
        },
        on_file_complete(file: File) {
          term.writeln(`\r\n\x1b[32m[Zmodem]\x1b[0m 上传成功: \x1b[1m${file.name}\x1b[0m (${file.size} bytes)`);
        },
      })
        .then(() => {
          session.close();
          document.body.removeChild(fileInput);
          onStatusChange?.({ active: false });
        })
        .catch((err: any) => {
          console.error('[Zmodem] Send batch error:', err);
          term.writeln(`\r\n\x1b[31m[Zmodem Error]\x1b[0m 上传失败: ${err.message || err}`);
          session.close();
          document.body.removeChild(fileInput);
          onStatusChange?.({ active: false });
        });
    };

    fileInput.click();
  }

  return {
    consume(data: ArrayBuffer | Uint8Array) {
      const buffer = data instanceof ArrayBuffer ? data : data.buffer;
      sentry.consume(buffer);
    },
    hasActiveSession() {
      return !!sentry.get_confirmed_session();
    },
  };
}
