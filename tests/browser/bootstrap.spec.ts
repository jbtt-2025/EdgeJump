import { test, expect } from '@playwright/test';

test('demo bootstrap accepts short input and shows actionable errors with a request number', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route('**/api/auth/bootstrap/status', (route) => route.fulfill({ json: { bootstrapNeeded: true, deployType: 'demo' } }));
  let attempts = 0;
  await page.route('**/api/auth/bootstrap', (route) => {
    attempts++;
    expect(route.request().postDataJSON()).toMatchObject({ username: 'a', password: '1' });
    return route.fulfill(attempts === 1 ? {
      status: 403,
      json: { error: '初始化令牌不正确或未填写，请使用部署时配置的 BOOTSTRAP_TOKEN。', code: 'BOOTSTRAP_TOKEN_INVALID' },
    } : {
      status: 503,
      json: { error: '管理员密码处理服务不可用，请检查 PASSWORD_KDF 绑定、DO 迁移及可用额度后重试。', code: 'BOOTSTRAP_PASSWORD_SERVICE_UNAVAILABLE', requestId: '47ed564a-ef37-4f63-9ceb-570fb37b38ac' },
    });
  });
  await page.goto('/');
  await expect(page.getByRole('button', { name: '初始化系统', exact: true })).toBeEnabled();
  await page.getByLabel('Bootstrap Token', { exact: true }).fill('test-token');
  await page.getByLabel('用户名', { exact: true }).fill('a');
  await page.getByLabel('密码', { exact: true }).fill('1');
  await page.getByRole('button', { name: '初始化系统', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('初始化失败');
  await expect(page.getByRole('alert')).toContainText('初始化令牌不正确');
  await expect(page.getByText('至少 8 个字符', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: '初始化系统', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('PASSWORD_KDF');
  await expect(page.getByRole('alert')).toContainText('47ed564a-ef37-4f63-9ceb-570fb37b38ac');
  await expect(page.getByRole('alert')).toBeInViewport();
  await page.getByRole('button', { name: '初始化系统', exact: true }).scrollIntoViewIfNeeded();
  await expect(page.getByRole('button', { name: '初始化系统', exact: true })).toBeInViewport();
  await page.getByRole('alert').scrollIntoViewIfNeeded();
  await page.screenshot({ path: testInfo.outputPath('bootstrap-error-mobile.png'), fullPage: true });
  expect(attempts).toBe(2);
});

test('initialization status errors remain visible and can be retried', async ({ page }, testInfo) => {
  let checks = 0;
  await page.route('**/api/auth/bootstrap/status', (route) => route.fulfill(++checks === 1 ? {
    status: 503,
    json: { error: '初始化所需的数据库表或字段缺失，请先完成 D1 数据库迁移，再重新初始化。', code: 'BOOTSTRAP_SCHEMA_MISSING', requestId: '8c826b28-d51c-46d3-af2c-bfc26fe2eb7a' },
  } : { json: { bootstrapNeeded: true, deployType: 'production' } }));
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('无法检查初始化状态');
  await expect(page.getByRole('alert')).toContainText('D1 数据库迁移');
  await page.screenshot({ path: testInfo.outputPath('bootstrap-status-error.png'), fullPage: true });
  await page.getByRole('button', { name: '重新检查', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveCount(0);
  await expect(page.getByRole('button', { name: '初始化系统', exact: true })).toBeEnabled();
  await expect(page.getByLabel('用户名', { exact: true })).toHaveAttribute('minlength', '3');
  await expect(page.getByLabel('密码', { exact: true })).toHaveAttribute('minlength', '8');
});

test('a completed bootstrap followed by a login failure offers login without repeating initialization', async ({ page }, testInfo) => {
  let bootstraps = 0;
  await page.route('**/api/auth/bootstrap/status', (route) => route.fulfill({ json: { bootstrapNeeded: true, deployType: 'production' } }));
  await page.route('**/api/auth/bootstrap', (route) => {
    bootstraps++;
    return route.fulfill({ status: 201, json: { success: true } });
  });
  await page.route('**/api/auth/login', (route) => route.fulfill({ status: 503, json: { error: '登录服务暂时不可用，请稍后重试。' } }));
  await page.goto('/');
  await page.getByLabel('Bootstrap Token', { exact: true }).fill('test-token');
  await page.getByLabel('用户名', { exact: true }).fill('admin');
  await page.getByLabel('密码', { exact: true }).fill('Browser-test-password-42!');
  await page.getByRole('button', { name: '初始化系统', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('管理员已创建，自动登录失败');
  await expect(page.getByLabel('Bootstrap Token', { exact: true })).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath('bootstrap-login-retry.png'), fullPage: true });
  await page.unroute('**/api/auth/login');
  await page.getByRole('button', { name: '立即登录', exact: true }).click();
  await expect(page.getByRole('heading', { name: '双因素认证', exact: true })).toBeVisible();
  expect(bootstraps).toBe(1);
});
