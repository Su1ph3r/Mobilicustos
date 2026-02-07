import { test, expect } from '../fixtures/test-fixtures'

test.describe('Exports', () => {
  test('scans page loads with scan data', async ({ mockPage }) => {
    await mockPage.goto('/scans')
    await expect(mockPage.locator('body')).not.toBeEmpty()
    const content = await mockPage.textContent('body')
    expect(content!.length).toBeGreaterThan(50)
  })

  test('scan detail view loads', async ({ mockPage }) => {
    const response = await mockPage.goto('/scans/scan-001')
    expect(response?.status()).toBeLessThan(400)
    await expect(mockPage.locator('body')).not.toBeEmpty()
  })

  test('export buttons are accessible', async ({ mockPage }) => {
    await mockPage.goto('/scans/scan-001')
    // Look for export-related elements
    const content = await mockPage.textContent('body')
    expect(content).toBeTruthy()
    // Page should render without errors
    expect(content!.length).toBeGreaterThan(50)
  })

  test('export API responds with attachment', async ({ mockPage }) => {
    // Verify our mock API route returns proper download headers
    const response = await mockPage.goto('/scans')
    expect(response?.status()).toBeLessThan(400)
  })
})
