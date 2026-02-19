<script setup lang="ts">
/**
 * AppLayout - Main application layout shell with collapsible sidebar navigation.
 *
 * Features:
 * - Responsive sidebar with expand/collapse toggle and mobile slide-out menu
 * - Navigation items with active route highlighting and keyboard shortcuts
 * - Dark mode toggle with localStorage persistence
 * - Mobile-specific header with hamburger menu and overlay backdrop
 * - Sidebar footer with shortcuts help, theme toggle, and collapse button
 * - Keyboard shortcuts integration via useKeyboardShortcuts composable
 *
 * @requires useKeyboardShortcuts - provides keyboard shortcut handling and help dialog
 * @requires KeyboardShortcutsHelp - shortcuts reference dialog component
 */
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import Button from 'primevue/button'
import { useKeyboardShortcuts } from '@/composables/useKeyboardShortcuts'
import KeyboardShortcutsHelp from './KeyboardShortcutsHelp.vue'

const router = useRouter()
const route = useRoute()
const darkMode = ref(false)
const sidebarCollapsed = ref(false)
const mobileMenuOpen = ref(false)
const isMobile = ref(false)

// Keyboard shortcuts
const { showShortcutsHelp } = useKeyboardShortcuts()

const menuItems = [
  { label: 'Dashboard', icon: 'pi pi-home', route: '/', shortcut: 'Alt+D' },
  { label: 'Apps', icon: 'pi pi-mobile', route: '/apps', shortcut: 'Alt+A' },
  { label: 'Scans', icon: 'pi pi-search', route: '/scans', shortcut: 'Alt+S' },
  { label: 'Findings', icon: 'pi pi-exclamation-triangle', route: '/findings', shortcut: 'Alt+F' },
  { label: 'Devices', icon: 'pi pi-tablet', route: '/devices', shortcut: 'Alt+V' },
  { label: 'Frida', icon: 'pi pi-code', route: '/frida', shortcut: 'Alt+R' },
  { label: 'Drozer', icon: 'pi pi-android', route: '/drozer', shortcut: '' },
  { label: 'Objection', icon: 'pi pi-wrench', route: '/objection', shortcut: '' },
  { label: 'Compliance', icon: 'pi pi-check-square', route: '/compliance', shortcut: 'Alt+C' },
  { label: 'Attack Paths', icon: 'pi pi-sitemap', route: '/attack-paths', shortcut: 'Alt+P' },
  { label: 'Secrets', icon: 'pi pi-key', route: '/secrets', shortcut: 'Alt+K' },
  { label: 'Scheduled Scans', icon: 'pi pi-clock', route: '/scheduled-scans', shortcut: '' },
  { label: 'Webhooks', icon: 'pi pi-bolt', route: '/webhooks', shortcut: '' },
  { label: 'Bypass', icon: 'pi pi-shield', route: '/bypass', shortcut: '' },
  { label: 'Burp Suite', icon: 'pi pi-server', route: '/burp', shortcut: '' },
  { label: 'API Endpoints', icon: 'pi pi-link', route: '/api-endpoints', shortcut: '' },
  { label: 'Settings', icon: 'pi pi-cog', route: '/settings', shortcut: '' },
]

// Check if mobile on mount and resize
function checkMobile() {
  isMobile.value = window.innerWidth < 768
  if (isMobile.value) {
    sidebarCollapsed.value = true
  }
}

// Load preferences from localStorage on mount
onMounted(() => {
  checkMobile()
  window.addEventListener('resize', checkMobile)

  const savedDarkMode = localStorage.getItem('darkMode')
  const savedSidebarCollapsed = localStorage.getItem('sidebarCollapsed')

  if (savedDarkMode === 'true') {
    darkMode.value = true
    document.documentElement.classList.add('dark-mode')
  }

  if (savedSidebarCollapsed === 'true' && !isMobile.value) {
    sidebarCollapsed.value = true
  }
})

// Clean up resize event listener
onUnmounted(() => {
  window.removeEventListener('resize', checkMobile)
})

function isActive(itemRoute: string) {
  if (itemRoute === '/') {
    return route.path === '/'
  }
  return route.path.startsWith(itemRoute)
}

function navigateTo(itemRoute: string) {
  router.push(itemRoute)
  if (isMobile.value) {
    mobileMenuOpen.value = false
  }
}

function toggleDarkMode() {
  darkMode.value = !darkMode.value
  localStorage.setItem('darkMode', String(darkMode.value))
  if (darkMode.value) {
    document.documentElement.classList.add('dark-mode')
  } else {
    document.documentElement.classList.remove('dark-mode')
  }
}

function toggleSidebar() {
  if (isMobile.value) {
    mobileMenuOpen.value = !mobileMenuOpen.value
  } else {
    sidebarCollapsed.value = !sidebarCollapsed.value
    localStorage.setItem('sidebarCollapsed', String(sidebarCollapsed.value))
  }
}

function closeMobileMenu() {
  mobileMenuOpen.value = false
}
</script>

<template>
  <div class="app-layout" :class="{ 'mobile': isMobile }">
    <!-- Mobile Header -->
    <header class="mobile-header" v-if="isMobile">
      <button class="menu-toggle" @click="toggleSidebar" aria-label="Toggle menu">
        <i class="pi pi-bars"></i>
      </button>
      <div class="mobile-logo">
        <i class="pi pi-shield"></i>
        <span>Mobilicustos</span>
      </div>
      <button class="theme-toggle" @click="toggleDarkMode" :aria-label="darkMode ? 'Switch to light mode' : 'Switch to dark mode'">
        <i :class="darkMode ? 'pi pi-sun' : 'pi pi-moon'"></i>
      </button>
    </header>

    <!-- Mobile Menu Overlay -->
    <div
      v-if="isMobile && mobileMenuOpen"
      class="mobile-overlay"
      @click="closeMobileMenu"
    ></div>

    <!-- Sidebar -->
    <aside
      class="sidebar"
      :class="{
        collapsed: sidebarCollapsed && !isMobile,
        'mobile-open': mobileMenuOpen && isMobile
      }"
      role="navigation"
      aria-label="Main navigation"
    >
      <div class="sidebar-header" v-if="!isMobile">
        <div class="logo" v-if="!sidebarCollapsed">
          <i class="pi pi-shield"></i>
          <span class="logo-text">Mobilicustos</span>
        </div>
        <div class="logo-icon" v-else>
          <i class="pi pi-shield"></i>
        </div>
      </div>

      <nav class="sidebar-nav">
        <button
          v-for="item in menuItems"
          :key="item.route"
          class="nav-item"
          :class="{ active: isActive(item.route) }"
          @click="navigateTo(item.route)"
          :title="sidebarCollapsed && !isMobile ? item.label : ''"
          :aria-current="isActive(item.route) ? 'page' : undefined"
          tabindex="0"
          data-navigable
        >
          <i :class="item.icon"></i>
          <span v-if="!sidebarCollapsed || isMobile" class="nav-label">{{ item.label }}</span>
        </button>
      </nav>

      <div class="sidebar-footer" v-if="!isMobile">
        <button
          class="nav-item"
          @click="showShortcutsHelp = true"
          :title="sidebarCollapsed ? 'Keyboard Shortcuts' : ''"
        >
          <i class="pi pi-question-circle"></i>
          <span v-if="!sidebarCollapsed" class="nav-label">Shortcuts</span>
        </button>
        <button
          class="nav-item"
          @click="toggleDarkMode"
          :title="darkMode ? 'Light Mode' : 'Dark Mode'"
        >
          <i :class="darkMode ? 'pi pi-sun' : 'pi pi-moon'"></i>
          <span v-if="!sidebarCollapsed" class="nav-label">{{ darkMode ? 'Light' : 'Dark' }}</span>
        </button>
        <button class="nav-item collapse-btn" @click="toggleSidebar">
          <i :class="sidebarCollapsed ? 'pi pi-angle-right' : 'pi pi-angle-left'"></i>
          <span v-if="!sidebarCollapsed" class="nav-label">Collapse</span>
        </button>
      </div>
    </aside>

    <!-- Main Content -->
    <div class="main-wrapper">
      <main class="app-main" role="main">
        <slot></slot>
      </main>
    </div>

    <!-- Keyboard Shortcuts Help Dialog -->
    <KeyboardShortcutsHelp v-model:visible="showShortcutsHelp" />
  </div>
</template>

<style scoped>
.app-layout {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

/* Mobile Layout */
.app-layout.mobile {
  flex-direction: column;
}

/* Mobile Header */
.mobile-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 56px;
  padding: 0 1rem;
  background: var(--surface-card);
  border-bottom: 1px solid var(--surface-border);
  position: sticky;
  top: 0;
  z-index: 100;
}

.menu-toggle,
.theme-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  border: none;
  background: transparent;
  color: var(--text-color);
  cursor: pointer;
  border-radius: 8px;
  transition: background 0.15s ease;
}

.menu-toggle:hover,
.theme-toggle:hover {
  background: var(--surface-hover);
}

.mobile-logo {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-family: var(--font-heading, 'Jost', sans-serif);
  font-weight: 700;
  color: var(--primary-color);
}

.mobile-logo i {
  font-size: 1.25rem;
}

/* Mobile Overlay */
.mobile-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  z-index: 998;
  animation: fadeIn 0.2s ease;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

/* Sidebar Styles */
.sidebar {
  width: 260px;
  background: var(--surface-card);
  border-right: 1px solid var(--surface-border);
  display: flex;
  flex-direction: column;
  transition: width 0.2s ease, transform 0.2s ease;
  flex-shrink: 0;
}

.sidebar.collapsed {
  width: 64px;
}

/* Mobile Sidebar */
.mobile .sidebar {
  position: fixed;
  top: 56px;
  left: 0;
  bottom: 0;
  width: 280px;
  z-index: 999;
  transform: translateX(-100%);
  border-right: none;
  box-shadow: 2px 0 10px rgba(0, 0, 0, 0.1);
}

.mobile .sidebar.mobile-open {
  transform: translateX(0);
}

.sidebar-header {
  padding: 1rem;
  border-bottom: 1px solid var(--surface-border);
  height: 64px;
  display: flex;
  align-items: center;
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-family: var(--font-heading, 'Jost', sans-serif);
  font-weight: 700;
  font-size: 1.1rem;
  color: var(--primary-color);
}

.logo i {
  font-size: 1.5rem;
}

.logo-text {
  font-weight: 800;
  background: linear-gradient(135deg, #6366f1, #8b5cf6);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.logo-icon {
  display: flex;
  justify-content: center;
  width: 100%;
}

.logo-icon i {
  font-size: 1.5rem;
  color: var(--primary-color);
}

.sidebar-nav {
  flex: 1;
  padding: 0.5rem;
  overflow-y: auto;
  -webkit-overflow-scrolling: touch;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  width: 100%;
  padding: 0.75rem 1rem;
  border: none;
  background: transparent;
  color: var(--text-color);
  font-family: var(--font-body, 'Jost', sans-serif);
  font-weight: 500;
  font-size: 0.9rem;
  cursor: pointer;
  border-radius: 8px;
  transition: all 0.15s ease;
  text-align: left;
  margin-bottom: 2px;
}

.nav-item:hover {
  background: var(--surface-hover);
}

.nav-item:focus-visible {
  outline: 2px solid var(--primary-color);
  outline-offset: 2px;
}

.nav-item.active {
  background: var(--primary-color);
  color: white;
}

.nav-item i {
  font-size: 1.1rem;
  width: 20px;
  text-align: center;
  flex-shrink: 0;
}

.nav-label {
  flex: 1;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.nav-shortcut {
  font-size: 0.75rem;
  color: var(--text-color-secondary);
  background: var(--surface-100);
  padding: 0.125rem 0.375rem;
  border-radius: 4px;
  font-family: var(--font-mono, 'Source Code Pro', monospace);
}

.nav-item.active .nav-shortcut {
  color: rgba(255, 255, 255, 0.8);
  background: rgba(255, 255, 255, 0.2);
}

.collapsed .nav-item {
  justify-content: center;
  padding: 0.75rem;
}

.collapsed .nav-item i {
  width: auto;
}

.sidebar-footer {
  padding: 0.5rem;
  border-top: 1px solid var(--surface-border);
}

.collapse-btn {
  margin-top: 0.25rem;
}

/* Main Content */
.main-wrapper {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  min-width: 0;
}

.app-main {
  flex: 1;
  padding: 1.5rem 2rem;
  overflow-y: auto;
  background: var(--surface-ground);
  -webkit-overflow-scrolling: touch;
}

/* Mobile Main Content */
.mobile .main-wrapper {
  height: calc(100vh - 56px);
}

.mobile .app-main {
  padding: 1rem;
}

/* Responsive Adjustments */
@media (max-width: 576px) {
  .app-main {
    padding: 0.75rem;
  }
}

/* Touch-friendly button sizes on mobile */
@media (max-width: 768px) {
  .nav-item {
    padding: 0.875rem 1rem;
    min-height: 48px;
  }
}

/* Reduced motion */
@media (prefers-reduced-motion: reduce) {
  .sidebar,
  .mobile-overlay,
  .nav-item {
    transition: none;
  }
}

/* High contrast mode */
@media (prefers-contrast: high) {
  .nav-item:focus-visible {
    outline-width: 3px;
  }

  .nav-item.active {
    outline: 2px solid white;
  }
}
</style>
