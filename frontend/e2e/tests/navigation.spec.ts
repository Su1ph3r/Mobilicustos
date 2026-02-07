import { test, expect } from '../fixtures/test-fixtures'

const routes = [
  { path: '/', name: 'dashboard' },
  { path: '/apps', name: 'apps' },
  { path: '/scans', name: 'scans' },
  { path: '/findings', name: 'findings' },
  { path: '/devices', name: 'devices' },
  { path: '/frida', name: 'frida' },
  { path: '/compliance', name: 'compliance' },
  { path: '/attack-paths', name: 'attack-paths' },
  { path: '/secrets', name: 'secrets' },
  { path: '/drozer', name: 'drozer' },
  { path: '/objection', name: 'objection' },
  { path: '/scheduled-scans', name: 'scheduled-scans' },
  { path: '/webhooks', name: 'webhooks' },
  { path: '/burp', name: 'burp' },
  { path: '/bypass', name: 'bypass' },
  { path: '/api-endpoints', name: 'api-endpoints' },
  { path: '/settings', name: 'settings' },
]

test.describe('Navigation smoke tests', () => {
  for (const route of routes) {
    test(`${route.name} route loads (${route.path})`, async ({ mockPage }) => {
      const response = await mockPage.goto(route.path)
      expect(response?.status()).toBeLessThan(400)
      // Page should not show a blank white screen
      const body = mockPage.locator('body')
      await expect(body).not.toBeEmpty()
    })
  }

  test('navigating between routes updates URL', async ({ mockPage }) => {
    await mockPage.goto('/')

    // Find and click a navigation link to findings
    const findingsLink = mockPage.locator('a[href="/findings"], [data-route="findings"]').first()
    if (await findingsLink.isVisible()) {
      await findingsLink.click()
      await expect(mockPage).toHaveURL(/\/findings/)
    }
  })
})
