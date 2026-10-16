import { test, expect } from '@playwright/test';

const SSH_PASSWORD = 'fixture-ssh-password';

test('machine, account and credential creation stay connected and administrators can connect immediately', async ({ page }, testInfo) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.context().addCookies([{ name: 'edgejump_test_demo', value: '1', url: 'http://127.0.0.1:4173' }]);
  await page.goto('/');
  await page.getByLabel('用户名', { exact: true }).fill('d');
  await page.getByLabel('密码', { exact: true }).fill('1');
  await page.getByRole('button', { name: '立即登录', exact: true }).click();
  await page.getByRole('button', { name: '堡垒机管理', exact: true }).click();
  await page.getByRole('button', { name: '新建主机资产', exact: true }).click();
  await page.getByLabel('名称', { exact: true }).fill('linked-machine');
  await page.getByLabel('公网 IP / 域名', { exact: true }).fill('8.8.8.8');
  await page.getByRole('button', { name: '新建 SSH 账号', exact: true }).click();
  await page.getByLabel('SSH 用户名', { exact: true }).fill('deploy');
  await page.getByRole('combobox', { name: '绑定凭证', exact: true }).selectOption('__new__');
  await page.getByLabel('SSH 密码', { exact: true }).fill(SSH_PASSWORD);
  await page.screenshot({ path: testInfo.outputPath('machine-with-account.png'), fullPage: true });
  const machineCreated = page.waitForResponse((response) => response.url().endsWith('/api/admin/assets') && response.request().method() === 'POST');
  await page.getByRole('button', { name: '保存', exact: true }).click();
  const machine = await (await machineCreated).json();
  const row = page.getByRole('row').filter({ has: page.getByText('linked-machine', { exact: true }) });
  await expect(row).toBeVisible();
  await expect(row.getByRole('button', { name: 'deploy', exact: true })).toBeVisible();

  // Reusing an account on another machine keeps the original binding and credential.
  await page.getByRole('button', { name: '新建主机资产', exact: true }).click();
  await page.getByLabel('名称', { exact: true }).fill('reuse-machine');
  await page.getByLabel('公网 IP / 域名', { exact: true }).fill('8.8.4.4');
  await page.getByLabel('复用已有 SSH 账号', { exact: true }).selectOption(machine.accounts[0].id);
  await expect(page.getByRole('region', { name: 'SSH 账号 1', exact: true })).toContainText('来自 linked-machine');
  await page.getByRole('button', { name: '保存', exact: true }).click();
  await expect(page.getByRole('row').filter({ has: page.getByText('reuse-machine', { exact: true }) })).toContainText('deploy');

  // A machine row preselects the target, and an account can create its credential inline.
  await row.getByRole('button', { name: '＋ 添加账号', exact: true }).click();
  await expect(page.getByRole('combobox', { name: '目标资产', exact: true })).toHaveValue(machine.id);
  await page.getByLabel('SSH 用户名', { exact: true }).fill('service');
  await page.getByRole('combobox', { name: '绑定凭证', exact: true }).selectOption('__new__');
  await page.getByRole('combobox', { name: '凭证类型', exact: true }).selectOption('private_key');
  await page.getByLabel('SSH 私钥', { exact: true }).fill('test-private-key-inline');
  await page.getByRole('button', { name: '保存', exact: true }).click();
  await expect(row.getByRole('button', { name: 'service', exact: true })).toBeVisible();

  // Starting with a credential offers the next step without reselecting that credential.
  await page.getByRole('button', { name: '凭证', exact: true }).click();
  await page.getByRole('button', { name: '新建凭证', exact: true }).click();
  await page.getByLabel('名称', { exact: true }).fill('linked-credential');
  await page.getByLabel('新凭证内容', { exact: true }).fill('another-write-only-secret');
  await page.getByRole('button', { name: '保存并添加账号', exact: true }).click();
  await expect(page.getByRole('form', { name: '新建SSH 账号', exact: true })).toBeVisible();
  await expect(page.getByRole('combobox', { name: '绑定凭证', exact: true }).locator('option:checked')).toHaveText('linked-credential · 密码');
  await page.getByLabel('SSH 用户名', { exact: true }).fill('ops');
  await page.getByRole('button', { name: '＋ 新建机器并绑定此账号', exact: true }).click();
  await page.getByLabel('名称', { exact: true }).fill('account-first-machine');
  await page.getByLabel('公网 IP / 域名', { exact: true }).fill('1.0.0.1');
  await expect(page.getByLabel('SSH 用户名', { exact: true })).toHaveValue('ops');
  await page.getByRole('button', { name: '保存', exact: true }).click();
  await expect(page.getByRole('form', { name: '新建主机资产', exact: true })).toHaveCount(0);

  await page.getByRole('button', { name: '资产控制台', exact: true }).click();
  const assetCard = page.locator('div').filter({ has: page.getByRole('heading', { name: 'linked-machine', exact: true }) })
    .filter({ has: page.getByRole('button', { name: '打开 Web Terminal', exact: true }) }).last();
  await assetCard.getByRole('button', { name: '打开 Web Terminal', exact: true }).click();
  await page.getByRole('radio', { name: /deploy/ }).check();
  await page.getByRole('button', { name: '启动终端', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('在线');
  await page.getByRole('button', { name: '断开会话', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'account-first-machine', exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('administrator-all-machines.png'), fullPage: true });
  expect(errors).toEqual([]);
});
