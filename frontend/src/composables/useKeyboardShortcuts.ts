/**
 * Keyboard Shortcuts Composable
 *
 * Provides global keyboard navigation and shortcuts
 */

import { onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'

interface KeyboardShortcut {
  key: string
  ctrl?: boolean
  alt?: boolean
  shift?: boolean
  action: () => void
  description: string
}

export function useKeyboardShortcuts() {
  const router = useRouter()
  const showShortcutsHelp = ref(false)

  // Define keyboard shortcuts
  const shortcuts: KeyboardShortcut[] = [
    // Navigation shortcuts (Alt + key)
    { key: 'd', alt: true, action: () => router.push('/'), description: 'Go to Dashboard' },
    { key: 'a', alt: true, action: () => router.push('/apps'), description: 'Go to Apps' },
    { key: 's', alt: true, action: () => router.push('/scans'), description: 'Go to Scans' },
    { key: 'f', alt: true, action: () => router.push('/findings'), description: 'Go to Findings' },
    { key: 'v', alt: true, action: () => router.push('/devices'), description: 'Go to Devices' },
    { key: 'r', alt: true, action: () => router.push('/frida'), description: 'Go to Frida' },
    { key: 'c', alt: true, action: () => router.push('/compliance'), description: 'Go to Compliance' },
    { key: 'p', alt: true, action: () => router.push('/attack-paths'), description: 'Go to Attack Paths' },
    { key: 'k', alt: true, action: () => router.push('/secrets'), description: 'Go to Secrets' },

    // Action shortcuts
    { key: '/', ctrl: true, action: () => focusGlobalSearch(), description: 'Focus search' },
    { key: 'n', ctrl: true, action: () => openNewDialog(), description: 'New item' },
    { key: '?', shift: true, action: () => { showShortcutsHelp.value = true }, description: 'Show shortcuts help' },
    { key: 'Escape', action: () => closeModals(), description: 'Close dialog/modal' },
  ]

  function handleKeyDown(event: KeyboardEvent) {
    // Don't trigger shortcuts when typing in input fields
    const target = event.target as HTMLElement
    if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
      // Only handle Escape in input fields
      if (event.key === 'Escape') {
        (target as HTMLInputElement).blur()
      }
      return
    }

    for (const shortcut of shortcuts) {
      const keyMatches = event.key.toLowerCase() === shortcut.key.toLowerCase()
      const ctrlMatches = shortcut.ctrl ? (event.ctrlKey || event.metaKey) : !(event.ctrlKey || event.metaKey)
      const altMatches = shortcut.alt ? event.altKey : !event.altKey
      const shiftMatches = shortcut.shift ? event.shiftKey : !event.shiftKey

      if (keyMatches && ctrlMatches && altMatches && shiftMatches) {
        event.preventDefault()
        shortcut.action()
        return
      }
    }
  }

  function focusGlobalSearch() {
    const searchInput = document.querySelector('[data-search-input]') as HTMLInputElement
    if (searchInput) {
      searchInput.focus()
    }
  }

  function openNewDialog() {
    // Emit custom event for new dialog
    window.dispatchEvent(new CustomEvent('keyboard:new'))
  }

  function closeModals() {
    // Close any open PrimeVue dialogs
    const escapeEvent = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })
    document.dispatchEvent(escapeEvent)
    showShortcutsHelp.value = false
  }

  onMounted(() => {
    window.addEventListener('keydown', handleKeyDown)
  })

  onUnmounted(() => {
    window.removeEventListener('keydown', handleKeyDown)
  })

  return {
    shortcuts,
    showShortcutsHelp,
  }
}

/**
 * Focus trap composable for accessible modals
 */
export function useFocusTrap(containerRef: { value: HTMLElement | null }) {
  const focusableSelector = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'

  function trapFocus(event: KeyboardEvent) {
    if (!containerRef.value || event.key !== 'Tab') return

    const focusableElements = containerRef.value.querySelectorAll(focusableSelector)
    const firstElement = focusableElements[0] as HTMLElement
    const lastElement = focusableElements[focusableElements.length - 1] as HTMLElement

    if (event.shiftKey && document.activeElement === firstElement) {
      event.preventDefault()
      lastElement.focus()
    } else if (!event.shiftKey && document.activeElement === lastElement) {
      event.preventDefault()
      firstElement.focus()
    }
  }

  function activate() {
    if (containerRef.value) {
      const firstElement = containerRef.value.querySelector(focusableSelector) as HTMLElement
      if (firstElement) {
        firstElement.focus()
      }
      containerRef.value.addEventListener('keydown', trapFocus)
    }
  }

  function deactivate() {
    if (containerRef.value) {
      containerRef.value.removeEventListener('keydown', trapFocus)
    }
  }

  return { activate, deactivate }
}

/**
 * Arrow key navigation for lists
 */
export function useArrowNavigation(
  listRef: { value: HTMLElement | null },
  itemSelector: string = '[data-navigable]'
) {
  function handleKeyDown(event: KeyboardEvent) {
    if (!listRef.value) return

    const items = Array.from(listRef.value.querySelectorAll(itemSelector)) as HTMLElement[]
    const currentIndex = items.findIndex(item => item === document.activeElement)

    switch (event.key) {
      case 'ArrowDown':
      case 'j':
        event.preventDefault()
        const nextIndex = currentIndex < items.length - 1 ? currentIndex + 1 : 0
        items[nextIndex]?.focus()
        break

      case 'ArrowUp':
      case 'k':
        event.preventDefault()
        const prevIndex = currentIndex > 0 ? currentIndex - 1 : items.length - 1
        items[prevIndex]?.focus()
        break

      case 'Home':
        event.preventDefault()
        items[0]?.focus()
        break

      case 'End':
        event.preventDefault()
        items[items.length - 1]?.focus()
        break

      case 'Enter':
      case ' ':
        event.preventDefault()
        if (document.activeElement instanceof HTMLElement) {
          document.activeElement.click()
        }
        break
    }
  }

  onMounted(() => {
    if (listRef.value) {
      listRef.value.addEventListener('keydown', handleKeyDown)
    }
  })

  onUnmounted(() => {
    if (listRef.value) {
      listRef.value.removeEventListener('keydown', handleKeyDown)
    }
  })
}
