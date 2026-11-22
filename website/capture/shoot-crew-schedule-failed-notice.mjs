// Screenshots for the Bot profile's Schedules failed-run notice: an
// auto-paused job named with Resume, a user-paused failure with no notice,
// and two active failures, at a phone width.
//   node capture/shoot-crew-schedule-failed-notice.mjs [outDir] [port]
import { createServer } from 'vite'
import { chromium } from 'playwright-core'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'

const OUT = process.argv[2] || '/tmp/crew-schedule-failed-notice-shots'
const PORT = Number(process.argv[3] || 5179)
const CHROMIUM_PATH = process.env.CHROMIUM_PATH
mkdirSync(OUT, { recursive: true })

const server = await createServer({
  configFile: 'vite.config.ts',
  server: { port: PORT, strictPort: true, host: '127.0.0.1' },
})
await server.listen()
const browser = await chromium.launch({ executablePath: CHROMIUM_PATH, args: ['--no-sandbox'] })

for (const [scenario, theme] of [['auto', 'dark'], ['user', 'dark'], ['many', 'dark'], ['auto', 'light']]) {
  const ctx = await browser.newContext({ viewport: { width: 440, height: 560 }, deviceScaleFactor: 2, reducedMotion: 'reduce' })
  const page = await ctx.newPage()
  await page.goto(`http://127.0.0.1:${PORT}/capture/crew-schedule-failed-notice.html?scenario=${scenario}&theme=${theme}`)
  await page.waitForSelector('[data-testid="crew-schedule-list"]', { timeout: 20000 })
  await page.waitForTimeout(300)
  await page.locator('[data-capture-root]').screenshot({ path: join(OUT, `${scenario}-${theme}.png`) })
  console.log('shot', scenario, theme)
  await ctx.close()
}

await browser.close()
await server.close()
