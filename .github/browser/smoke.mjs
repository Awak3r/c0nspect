import { chromium } from 'playwright-core';
import { readFileSync } from 'node:fs';

const origin = 'http://127.0.0.1:18080';
const projectName = 'Browser smoke project';
const noteName = 'Browser smoke note';
const body = 'Disposable browser smoke content.';
let stage = 'start Chromium';
let browser;

try {
  const password = readFileSync(0, 'utf8').trim();
  const executablePath = process.env.CONSPECT_SMOKE_CHROMIUM;
  browser = await chromium.launch(executablePath ? { executablePath, timeout: 15000 } : { channel: 'chrome', timeout: 15000 });
  const session = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
  session.setDefaultTimeout(8000);
  const localOnly = route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort();
  await session.route('**/*', localOnly);
  const page = await session.newPage();
  stage = 'sign in and create a project';
  await page.goto(`${origin}/login`);
  await page.locator('#username').fill('smoke');
  await page.locator('#password').fill(password);
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  await page.waitForURL(`${origin}/projects`);
  await page.getByText('Новый проект', { exact: true }).click();
  await page.locator('#project-name').fill(projectName);
  await page.getByRole('button', { name: 'Создать проект', exact: true }).click();
  await page.getByRole('heading', { name: projectName, exact: true }).waitFor();

  stage = 'import a Markdown note';
  await page.locator('#import-files').setInputFiles({ name: 'smoke.md', mimeType: 'text/markdown', buffer: Buffer.from(`# ${noteName}\n\n${body}\n`) });
  await page.getByRole('button', { name: 'Загрузить', exact: true }).click();
  const row = page.getByRole('listitem').filter({ has: page.getByRole('link', { name: noteName, exact: true }) });
  await row.waitFor();
  const notePath = await row.getByRole('link', { name: noteName, exact: true }).getAttribute('href');

  stage = 'click Share and verify the clipboard';
  const share = row.getByRole('button', { name: `Поделиться по ссылке: ${noteName}`, exact: true });
  await share.click();
  await row.getByRole('status').filter({ hasText: /^Ссылка скопирована$/ }).waitFor();
  const url = await page.evaluate(() => navigator.clipboard.readText());
  const publicURL = new URL(url);
  if (publicURL.origin !== origin || !/^\/s\/[A-Za-z0-9_-]+$/.test(publicURL.pathname)) throw new Error();
  const anonymous = await browser.newContext();
  await anonymous.route('**/*', localOnly);
  const publicNote = await anonymous.newPage();
  await publicNote.goto(url, { timeout: 8000 });
  await publicNote.getByText(body, { exact: true }).waitFor({ timeout: 8000 });
  await anonymous.close();

  stage = 'open the trash confirmation without deleting';
  const confirm = row.getByRole('checkbox', { name: 'Подтверждаю удаление.' });
  if (await confirm.isVisible()) throw new Error();
  let deletionRequested = false;
  page.on('request', request => {
    if (request.method() === 'POST' && request.url() === `${origin}${notePath}/delete`) deletionRequested = true;
  });
  await row.locator('summary[aria-label]').click();
  await confirm.waitFor({ state: 'visible' });
  const readerStatus = (await session.request.get(`${origin}${notePath}`, { timeout: 8000 })).status();
  if (deletionRequested || await confirm.isChecked() || readerStatus !== 200) throw new Error();
  console.log('Browser smoke passed: native clipboard, anonymous reader and deletion confirmation.');
} catch {
  // Browser errors may include HTML, cookies or input values. Print only the static stage.
  console.error(`Browser smoke failed: ${stage}.`);
  process.exitCode = 1;
} finally {
  await browser?.close();
}
