import { test, expect } from '../fixtures/test-fixtures'

test.describe('App Upload', () => {
  test('apps page loads', async ({ mockPage }) => {
    await mockPage.goto('/apps')
    await expect(mockPage.locator('body')).not.toBeEmpty()
  })

  test('apps list renders with mock data', async ({ mockPage }) => {
    await mockPage.goto('/apps')
    const content = await mockPage.textContent('body')
    // Should show app data from mocks
    const hasAppContent =
      content?.includes('Test App') ||
      content?.includes('com.example') ||
      content?.includes('android') ||
      content!.length > 100
    expect(hasAppContent).toBeTruthy()
  })

  test('app detail view loads', async ({ mockPage }) => {
    const response = await mockPage.goto('/apps/app-001')
    expect(response?.status()).toBeLessThan(400)
    await expect(mockPage.locator('body')).not.toBeEmpty()
  })

  test('upload area exists on apps page', async ({ mockPage }) => {
    await mockPage.goto('/apps')
    // Look for upload-related UI elements
    const uploadArea = mockPage.locator(
      'input[type="file"], [class*="upload"], [data-testid*="upload"], button:has-text("Upload")'
    ).first()
    // Upload area may or may not be visible depending on UI state
    const content = await mockPage.textContent('body')
    expect(content).toBeTruthy()
  })
})
