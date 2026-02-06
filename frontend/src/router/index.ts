import { createRouter, createWebHistory } from 'vue-router'

/**
 * Application router configuration using HTML5 history mode.
 *
 * Routes are lazy-loaded via dynamic imports for code splitting.
 * Covers all primary views: dashboard, apps, scans, findings, devices,
 * Frida, Drozer, Objection, compliance, attack paths, secrets,
 * scheduled scans, webhooks, Burp Suite, bypass, API endpoints, and settings.
 */
const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      name: 'dashboard',
      component: () => import('@/views/DashboardView.vue'),
    },
    {
      path: '/apps',
      name: 'apps',
      component: () => import('@/views/AppsView.vue'),
    },
    {
      path: '/apps/:id',
      name: 'app-detail',
      component: () => import('@/views/AppDetailView.vue'),
    },
    {
      path: '/scans',
      name: 'scans',
      component: () => import('@/views/ScansView.vue'),
    },
    {
      path: '/scans/:id',
      name: 'scan-detail',
      component: () => import('@/views/ScanDetailView.vue'),
    },
    {
      path: '/findings',
      name: 'findings',
      component: () => import('@/views/FindingsView.vue'),
    },
    {
      path: '/findings/:id',
      name: 'finding-detail',
      component: () => import('@/views/FindingDetailView.vue'),
    },
    {
      path: '/devices',
      name: 'devices',
      component: () => import('@/views/DevicesView.vue'),
    },
    {
      path: '/frida',
      name: 'frida',
      component: () => import('@/views/FridaView.vue'),
    },
    {
      path: '/compliance',
      name: 'compliance',
      component: () => import('@/views/ComplianceView.vue'),
    },
    {
      path: '/attack-paths',
      name: 'attack-paths',
      component: () => import('@/views/AttackPathsView.vue'),
    },
    {
      path: '/secrets',
      name: 'secrets',
      component: () => import('@/views/SecretsView.vue'),
    },
    {
      path: '/drozer',
      name: 'drozer',
      component: () => import('@/views/DrozerView.vue'),
    },
    {
      path: '/objection',
      name: 'objection',
      component: () => import('@/views/ObjectionView.vue'),
    },
    {
      path: '/scheduled-scans',
      name: 'scheduled-scans',
      component: () => import('@/views/ScheduledScansView.vue'),
    },
    {
      path: '/webhooks',
      name: 'webhooks',
      component: () => import('@/views/WebhooksView.vue'),
    },
    {
      path: '/burp',
      name: 'burp',
      component: () => import('@/views/BurpView.vue'),
    },
    {
      path: '/bypass',
      name: 'bypass',
      component: () => import('@/views/BypassView.vue'),
    },
    {
      path: '/api-endpoints',
      name: 'api-endpoints',
      component: () => import('@/views/APIEndpointsView.vue'),
    },
    {
      path: '/settings',
      name: 'settings',
      component: () => import('@/views/SettingsView.vue'),
    },
  ],
})

export default router
