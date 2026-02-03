<template>
  <div class="remediation-panel">
    <h4>
      <i class="pi pi-wrench" />
      Remediation
    </h4>

    <!-- Basic Remediation Text -->
    <div class="remediation-text">
      <p>{{ finding.remediation || 'No remediation guidance available' }}</p>
    </div>

    <!-- OWASP References -->
    <div v-if="finding.owasp_masvs_control || finding.owasp_mastg_test" class="owasp-references">
      <div v-if="finding.owasp_masvs_control" class="reference-item">
        <span class="reference-label">MASVS Control:</span>
        <a
          :href="getMasvsUrl(finding.owasp_masvs_control)"
          target="_blank"
          rel="noopener"
          class="reference-link"
        >
          {{ finding.owasp_masvs_control }}
          <i class="pi pi-external-link" />
        </a>
      </div>
      <div v-if="finding.owasp_mastg_test" class="reference-item">
        <span class="reference-label">MASTG Test:</span>
        <a
          :href="getMastgUrl(finding.owasp_mastg_test)"
          target="_blank"
          rel="noopener"
          class="reference-link"
        >
          {{ finding.owasp_mastg_test }}
          <i class="pi pi-external-link" />
        </a>
      </div>
    </div>

    <!-- Remediation Commands -->
    <div
      v-if="finding.remediation_commands && finding.remediation_commands.length > 0"
      class="remediation-section"
    >
      <h5>Commands</h5>
      <div class="commands-list">
        <div v-for="(cmd, idx) in finding.remediation_commands" :key="idx" class="command-block">
          <div class="command-block-header">
            <div class="command-meta">
              <span v-if="cmd.type" class="command-type" :class="getTypeClass(cmd.type)">{{ cmd.type }}</span>
              <span v-if="cmd.description" class="command-description">{{ cmd.description }}</span>
            </div>
            <Button
              icon="pi pi-copy"
              class="p-button-text p-button-sm copy-btn"
              @click="copyCommand(cmd.command, idx)"
              v-tooltip.top="copiedIdx === idx ? 'Copied!' : 'Copy'"
            />
          </div>
          <pre class="command-code"><code>{{ cmd.command }}</code></pre>
        </div>
      </div>
    </div>

    <!-- Remediation Code Snippets -->
    <div v-if="hasRemediationCode" class="remediation-section">
      <h5>Code Examples</h5>
      <TabView class="code-tabs">
        <TabPanel v-for="(code, lang) in finding.remediation_code" :key="lang" :value="String(lang)" :header="formatLanguage(lang)">
          <div class="code-container">
            <pre class="code-block">{{ code }}</pre>
            <Button
              icon="pi pi-copy"
              class="p-button-text p-button-sm copy-code-btn"
              @click="copyCode(code, lang)"
              v-tooltip.top="copiedLang === lang ? 'Copied!' : 'Copy code'"
            />
          </div>
        </TabPanel>
      </TabView>
    </div>

    <!-- Remediation Resources -->
    <div
      v-if="finding.remediation_resources && finding.remediation_resources.length > 0"
      class="remediation-section"
    >
      <h5>Resources</h5>
      <ul class="resources-list">
        <li v-for="(resource, idx) in finding.remediation_resources" :key="idx" class="resource-item">
          <span class="resource-type" :class="getResourceTypeClass(resource.type)">
            <i :class="getResourceIcon(resource.type)" />
          </span>
          <a :href="resource.url" target="_blank" rel="noopener" class="resource-link">
            {{ resource.title }}
            <i class="pi pi-external-link" />
          </a>
        </li>
      </ul>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import Button from 'primevue/button'
import TabView from 'primevue/tabview'
import TabPanel from 'primevue/tabpanel'
import type { Finding } from '@/stores/findings'

const props = defineProps<{
  finding: Finding
}>()

const copiedIdx = ref<number | null>(null)
const copiedLang = ref<string | null>(null)

const hasRemediationCode = computed(() => {
  return props.finding.remediation_code && Object.keys(props.finding.remediation_code).length > 0
})

const formatLanguage = (lang: string): string => {
  const langMap: Record<string, string> = {
    kotlin: 'Kotlin',
    java: 'Java',
    swift: 'Swift',
    objc: 'Objective-C',
    xml: 'XML',
    gradle: 'Gradle',
    'xml-api31': 'XML (API 31+)',
    'xml-protected': 'XML (Protected)',
  }
  return langMap[lang.toLowerCase()] || lang.charAt(0).toUpperCase() + lang.slice(1)
}

const getTypeClass = (type: string): string => {
  const typeMap: Record<string, string> = {
    adb: 'type-adb',
    frida: 'type-frida',
    bash: 'type-bash',
    android: 'type-android',
    ios: 'type-ios',
    gradle: 'type-gradle',
  }
  return typeMap[type.toLowerCase()] || 'type-default'
}

const getResourceTypeClass = (type: string): string => {
  const typeMap: Record<string, string> = {
    documentation: 'resource-doc',
    blog: 'resource-blog',
    video: 'resource-video',
    github: 'resource-github',
    tool: 'resource-tool',
  }
  return typeMap[type.toLowerCase()] || 'resource-default'
}

const getResourceIcon = (type: string): string => {
  const iconMap: Record<string, string> = {
    documentation: 'pi pi-book',
    blog: 'pi pi-pencil',
    video: 'pi pi-video',
    github: 'pi pi-github',
    tool: 'pi pi-wrench',
  }
  return iconMap[type.toLowerCase()] || 'pi pi-link'
}

const getMasvsUrl = (control: string): string => {
  // MASVS controls format: MASVS-STORAGE-1
  return `https://mas.owasp.org/MASVS/controls/${control}/`
}

const getMastgUrl = (test: string): string => {
  // MASTG tests format: MASTG-TEST-0001
  return `https://mas.owasp.org/MASTG/tests/android/`
}

const copyCommand = async (command: string, idx: number) => {
  try {
    await navigator.clipboard.writeText(command)
    copiedIdx.value = idx
    setTimeout(() => {
      copiedIdx.value = null
    }, 2000)
  } catch {
    console.error('Failed to copy command')
  }
}

const copyCode = async (code: string, lang: string) => {
  try {
    await navigator.clipboard.writeText(code)
    copiedLang.value = lang
    setTimeout(() => {
      copiedLang.value = null
    }, 2000)
  } catch {
    console.error('Failed to copy code')
  }
}
</script>

<style scoped>
.remediation-panel {
  margin-bottom: var(--spacing-lg);
}

.remediation-panel h4 {
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--text-primary, var(--text-color));
  margin-bottom: var(--spacing-md);
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding-bottom: var(--spacing-sm);
  border-bottom: 1px solid var(--border-color);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.remediation-panel h4 i {
  color: var(--accent-primary, var(--primary-color));
  font-size: 0.875rem;
}

.remediation-text {
  margin-bottom: var(--spacing-lg);
}

.remediation-text p {
  color: var(--text-primary, var(--text-color));
  line-height: 1.7;
  font-size: 0.9375rem;
  margin: 0;
  white-space: pre-line;
}

.owasp-references {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
  padding: var(--spacing-md);
  background: var(--bg-tertiary, var(--surface-ground));
  border-radius: var(--radius-sm);
}

.reference-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.reference-label {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-secondary, var(--text-color-secondary));
  text-transform: uppercase;
}

.reference-link {
  font-size: 0.875rem;
  color: var(--accent-primary, var(--primary-color));
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.reference-link:hover {
  text-decoration: underline;
}

.reference-link i {
  font-size: 0.75rem;
  opacity: 0.7;
}

.remediation-section {
  margin-bottom: var(--spacing-lg);
}

.remediation-section:last-child {
  margin-bottom: 0;
}

.remediation-section h5 {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-secondary, var(--text-color-secondary));
  margin-bottom: var(--spacing-sm);
  text-transform: uppercase;
}

.commands-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.command-block {
  border-radius: 8px;
  overflow: hidden;
  background: #1e1e1e;
  border: 1px solid #3d3d3d;
}

.command-block-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem 1rem;
  background: #2d2d2d;
  border-bottom: 1px solid #3d3d3d;
}

.command-meta {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.command-code {
  margin: 0;
  padding: 1rem;
  overflow-x: auto;
  font-family: 'Fira Code', 'Monaco', 'Consolas', monospace;
  font-size: 0.875rem;
  line-height: 1.6;
  background: #1e1e1e;
}

.command-code code {
  color: #4ec9b0;
  background: transparent;
  white-space: pre-wrap;
  word-break: break-word;
}

.command-type {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  font-size: 0.6875rem;
  font-weight: 600;
  text-transform: uppercase;
}

.type-adb {
  background: rgba(34, 197, 94, 0.15);
  color: #22c55e;
}

.type-frida {
  background: rgba(168, 85, 247, 0.15);
  color: #a855f7;
}

.type-bash {
  background: rgba(59, 130, 246, 0.15);
  color: #3b82f6;
}

.type-android {
  background: rgba(163, 230, 53, 0.15);
  color: #a3e635;
}

.type-ios {
  background: rgba(156, 163, 175, 0.15);
  color: #9ca3af;
}

.type-gradle {
  background: rgba(34, 197, 94, 0.15);
  color: #22c55e;
}

.type-default {
  background: rgba(148, 163, 184, 0.15);
  color: #94a3b8;
}

.command-description {
  flex: 1;
  font-size: 0.8125rem;
  color: var(--text-secondary, var(--text-color-secondary));
}

.copy-btn {
  margin-left: auto;
  color: var(--text-tertiary) !important;
  background: transparent !important;
}

.copy-btn:hover {
  color: var(--text-primary) !important;
}

.code-block {
  background: #1e293b;
  color: #e2e8f0;
  padding: var(--spacing-md);
  font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 0.8125rem;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0;
}

.code-block.command {
  background: #0f172a;
  padding: var(--spacing-sm) var(--spacing-md);
  border-radius: 0;
}

.code-tabs {
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  overflow: hidden;
}

.code-tabs :deep(.p-tabview-nav) {
  background: var(--bg-tertiary, var(--surface-ground));
  border-bottom: 1px solid var(--border-color);
}

.code-tabs :deep(.p-tabview-panels) {
  padding: 0;
}

.code-tabs :deep(.p-tabview-panel) {
  padding: 0;
}

.code-container {
  position: relative;
}

.copy-code-btn {
  position: absolute;
  top: var(--spacing-sm);
  right: var(--spacing-sm);
  color: #94a3b8 !important;
  background: transparent !important;
}

.copy-code-btn:hover {
  color: #e2e8f0 !important;
  background: rgba(255, 255, 255, 0.1) !important;
}

.resources-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.resource-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--bg-tertiary, var(--surface-ground));
  border-radius: var(--radius-sm);
}

.resource-type {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: var(--radius-sm);
  font-size: 0.875rem;
}

.resource-doc {
  background: rgba(59, 130, 246, 0.15);
  color: #3b82f6;
}

.resource-blog {
  background: rgba(249, 115, 22, 0.15);
  color: #f97316;
}

.resource-video {
  background: rgba(239, 68, 68, 0.15);
  color: #ef4444;
}

.resource-github {
  background: rgba(156, 163, 175, 0.15);
  color: #9ca3af;
}

.resource-tool {
  background: rgba(168, 85, 247, 0.15);
  color: #a855f7;
}

.resource-default {
  background: rgba(148, 163, 184, 0.15);
  color: #94a3b8;
}

.resource-link {
  flex: 1;
  font-size: 0.875rem;
  color: var(--accent-primary, var(--primary-color));
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.resource-link:hover {
  text-decoration: underline;
}

.resource-link i {
  font-size: 0.75rem;
  opacity: 0.7;
}
</style>
