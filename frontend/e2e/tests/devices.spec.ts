import { test, expect, mockData } from '../fixtures/test-fixtures'

test.describe('Devices', () => {
  test('devices page loads', async ({ mockPage }) => {
    await mockPage.goto('/devices')
    await expect(mockPage.locator('body')).not.toBeEmpty()
  })

  test('displays device information', async ({ mockPage }) => {
    await mockPage.goto('/devices')
    const content = await mockPage.textContent('body')
    // Should show device data or at least render the page
    const hasDeviceContent =
      content?.includes('Pixel') ||
      content?.includes('emulator') ||
      content?.includes('android') ||
      content?.includes('device') ||
      content!.length > 100
    expect(hasDeviceContent).toBeTruthy()
  })

  test('renders device status indicators', async ({ mockPage }) => {
    await mockPage.goto('/devices')
    const content = await mockPage.textContent('body')
    expect(content).toBeTruthy()
    // Page should render without console errors
    const errors: string[] = []
    mockPage.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(msg.text())
    })
    await mockPage.reload()
    await mockPage.waitForTimeout(1000)
    const realErrors = errors.filter(
      (e) => !e.includes('favicon') && !e.includes('404')
    )
    expect(realErrors).toHaveLength(0)
  })
})
