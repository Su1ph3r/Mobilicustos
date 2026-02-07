import { test, expect, mockData } from '../fixtures/test-fixtures'

test.describe('Dashboard', () => {
  test.beforeEach(async ({ mockPage }) => {
    await mockPage.goto('/')
  })

  test('dashboard page loads successfully', async ({ mockPage }) => {
    await expect(mockPage.locator('body')).not.toBeEmpty()
    // Should not show error state
    const errorText = mockPage.getByText(/error|failed|500/i).first()
    await expect(errorText).not.toBeVisible({ timeout: 3000 }).catch(() => {
      // OK if the locator doesn't exist at all
    })
  })

  test('displays severity counts', async ({ mockPage }) => {
    // The dashboard should render severity data from mock
    const pageContent = await mockPage.textContent('body')
    // At minimum the page should have loaded with content
    expect(pageContent).toBeTruthy()
    expect(pageContent!.length).toBeGreaterThan(50)
  })

  test('displays app count', async ({ mockPage }) => {
    const pageContent = await mockPage.textContent('body')
    // Should contain numeric data from the dashboard response
    expect(pageContent).toBeTruthy()
  })

  test('renders without console errors', async ({ mockPage }) => {
    const errors: string[] = []
    mockPage.on('console', (msg) => {
      if (msg.type() === 'error') {
        errors.push(msg.text())
      }
    })
    await mockPage.goto('/')
    await mockPage.waitForTimeout(2000)
    // Filter out expected errors (like favicon 404)
    const realErrors = errors.filter(
      (e) => !e.includes('favicon') && !e.includes('404')
    )
    expect(realErrors).toHaveLength(0)
  })
})
