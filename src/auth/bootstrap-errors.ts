import { PasswordKdfUnavailableError } from './password-service.ts';

const errors = {
  BOOTSTRAP_COMPLETED: [403, 'System setup is already completed. Bootstrap is permanently disabled.', '系统已完成初始化，请使用已创建的管理员账号登录。'],
  BOOTSTRAP_TOKEN_NOT_CONFIGURED: [503, 'Bootstrap token is not configured', '初始化服务尚未配置 BOOTSTRAP_TOKEN，请在 Worker Secrets 中配置后重试。'],
  BOOTSTRAP_TOKEN_INVALID: [403, 'Invalid bootstrap token', '初始化令牌不正确或未填写，请使用部署时配置的 BOOTSTRAP_TOKEN。'],
  BOOTSTRAP_INVALID_REQUEST: [400, 'Invalid bootstrap request', '初始化请求格式不正确，请刷新页面后重新填写。'],
  BOOTSTRAP_USERNAME_REQUIRED: [400, 'Username is required', '请输入管理员用户名。'],
  BOOTSTRAP_USERNAME_TOO_SHORT: [400, 'Username must be at least 3 characters long', '管理员用户名至少需要 3 个字符。'],
  BOOTSTRAP_PASSWORD_REQUIRED: [400, 'Password is required', '请输入管理员密码。'],
  BOOTSTRAP_PASSWORD_TOO_SHORT: [400, 'Password must be at least 8 characters long', '管理员密码至少需要 8 个字符。'],
  BOOTSTRAP_SCHEMA_MISSING: [503, 'Bootstrap database migration is incomplete', '初始化所需的数据库表或字段缺失，请先完成 D1 数据库迁移，再重新初始化。'],
  BOOTSTRAP_STATUS_UNAVAILABLE: [503, 'Bootstrap status unavailable', '无法读取初始化状态，请检查 D1 数据库绑定及可用额度后重试。'],
  BOOTSTRAP_PASSWORD_SERVICE_UNAVAILABLE: [503, 'Bootstrap password service unavailable', '管理员密码处理服务不可用，请检查 PASSWORD_KDF 绑定、DO 迁移及可用额度后重试。'],
  BOOTSTRAP_SAVE_FAILED: [500, 'Bootstrap administrator save failed', '管理员配置保存失败，请按请求编号检查 Workers Logs 中的数据库错误。'],
  BOOTSTRAP_AUDIT_FAILED: [500, 'Bootstrap audit write failed', '管理员已创建，但初始化审计写入失败。请检查 D1 数据库状态，然后使用刚创建的账号登录。'],
} as const;

type BootstrapErrorCode = keyof typeof errors;

export class BootstrapError extends Error {
  readonly code: BootstrapErrorCode;
  readonly status: number;
  readonly publicMessage: string;

  constructor(code: BootstrapErrorCode, options?: ErrorOptions) {
    const [status, message, publicMessage] = errors[code];
    super(message, options);
    this.name = 'BootstrapError';
    this.code = code;
    this.status = status;
    this.publicMessage = publicMessage;
  }
}

export function bootstrapFailure(error: unknown, fallback: BootstrapErrorCode): BootstrapError {
  if (error instanceof BootstrapError) return error;
  if (fallback === 'BOOTSTRAP_AUDIT_FAILED') return new BootstrapError(fallback, { cause: error });
  if (error instanceof PasswordKdfUnavailableError) {
    return new BootstrapError('BOOTSTRAP_PASSWORD_SERVICE_UNAVAILABLE', { cause: error });
  }
  const cause = error instanceof Error && error.cause instanceof Error ? error.cause : null;
  if ([error, cause].some((value) => value instanceof Error && /no such (table|column):|has no column named/i.test(value.message))) {
    return new BootstrapError('BOOTSTRAP_SCHEMA_MISSING', { cause: error });
  }
  return new BootstrapError(fallback, { cause: error });
}
