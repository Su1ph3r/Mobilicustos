<template>
  <div class="poc-evidence">
    <TabView>
      <!-- Evidence Tab -->
      <TabPanel v-if="evidence" value="evidence" header="Evidence">
        <div class="evidence-content">
          <!-- Structured table for array data -->
          <div v-if="parsedEvidence" class="evidence-table-container">
            <table class="evidence-table">
              <thead>
                <tr>
                  <th v-for="col in evidenceColumns" :key="col">{{ formatColumnHeader(col) }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(row, idx) in parsedEvidence" :key="idx">
                  <td v-for="col in evidenceColumns" :key="col" :class="getColumnClass(col)">
                    {{ row[col] || '-' }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <!-- Code block for JSON/XML -->
          <CodeBlock v-else-if="isCodeEvidence(evidence)" :code="evidence" :language="detectEvidenceLanguage(evidence)" />
          <!-- Plain text -->
          <pre v-else class="evidence-text">{{ evidence }}</pre>
        </div>
      </TabPanel>

      <!-- Verification Steps Tab -->
      <TabPanel v-if="verification" value="verification" header="Verification">
        <div class="verification-content">
          <div class="verification-steps">
            <div
              v-for="(step, index) in verificationSteps"
              :key="index"
              class="verification-step"
            >
              <span class="step-number">{{ index + 1 }}</span>
              <span class="step-text">{{ step }}</span>
            </div>
          </div>
        </div>
      </TabPanel>

      <!-- Commands Tab -->
      <TabPanel v-if="commands && commands.length > 0" value="commands" header="Commands">
        <div class="commands-content">
          <div v-for="(cmd, index) in commands" :key="index" class="command-block">
            <div class="command-block-header">
              <div class="command-meta">
                <Tag v-if="cmd.type" :value="cmd.type" :severity="getCommandSeverity(cmd.type)" class="command-type-tag" />
                <span v-if="cmd.description" class="command-desc">{{ cmd.description }}</span>
              </div>
              <Button
                icon="pi pi-copy"
                class="p-button-sm p-button-text copy-btn"
                v-tooltip.top="'Copy command'"
                @click="copyCommand(cmd.command)"
              />
            </div>
            <pre class="command-code"><code>{{ cmd.command }}</code></pre>
          </div>
          <div class="copy-all-section">
            <Button
              label="Copy All Commands"
              icon="pi pi-copy"
              class="p-button-sm p-button-outlined"
              @click="copyAllCommands"
            />
          </div>
        </div>
      </TabPanel>

      <!-- Frida Script Tab -->
      <TabPanel v-if="fridaScript" value="frida" header="Frida Script">
        <div class="frida-content">
          <CodeBlock :code="fridaScript" language="javascript" />
          <div class="frida-actions">
            <Button
              label="Copy Script"
              icon="pi pi-copy"
              class="p-button-sm"
              @click="copyFridaScript"
            />
            <Button
              label="Use in Console"
              icon="pi pi-bolt"
              class="p-button-sm p-button-outlined"
              @click="useFridaScript"
            />
          </div>
        </div>
      </TabPanel>

      <!-- Screenshot Tab -->
      <TabPanel v-if="screenshotPath" value="screenshot" header="Screenshot">
        <div class="screenshot-content">
          <div class="screenshot-wrapper" @click="openLightbox">
            <img :src="screenshotUrl" :alt="'PoC Screenshot'" class="screenshot-image" />
            <div class="screenshot-overlay">
              <i class="pi pi-search-plus"></i>
              <span>Click to enlarge</span>
            </div>
          </div>
        </div>
      </TabPanel>
    </TabView>

    <!-- Lightbox Dialog -->
    <Dialog
      v-model:visible="showLightbox"
      :modal="true"
      :dismissableMask="true"
      :style="{ width: '90vw', maxWidth: '1200px' }"
      :header="'Screenshot'"
    >
      <div class="lightbox-content">
        <img :src="screenshotUrl" :alt="'PoC Screenshot'" class="lightbox-image" />
      </div>
    </Dialog>

    <Toast />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import Button from 'primevue/button'
import TabView from 'primevue/tabview'
import TabPanel from 'primevue/tabpanel'
import Dialog from 'primevue/dialog'
import Toast from 'primevue/toast'
import Tag from 'primevue/tag'
import CodeBlock from './CodeBlock.vue'

interface StructuredCommand {
  type: string
  command: string
  description?: string
}

const props = defineProps<{
  evidence?: string
  verification?: string
  commands?: StructuredCommand[]
  fridaScript?: string
  screenshotPath?: string
}>()

const router = useRouter()
const toast = useToast()
const showLightbox = ref(false)

// Parse verification steps from text
const verificationSteps = computed(() => {
  if (!props.verification) return []

  // Split by newlines and filter out empty lines
  return props.verification
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => {
      // Remove leading numbers like "1." or "1)"
      return line.replace(/^\d+[\.\)]\s*/, '')
    })
})

// Parse structured evidence (JSON array)
const parsedEvidence = computed(() => {
  if (!props.evidence) return null
  const trimmed = props.evidence.trim()
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    try {
      const parsed = JSON.parse(trimmed)
      if (Array.isArray(parsed) && parsed.length > 0 && typeof parsed[0] === 'object') {
        return parsed
      }
    } catch {
      // Not valid JSON array
    }
  }
  return null
})

// Get columns from parsed evidence
const evidenceColumns = computed(() => {
  if (!parsedEvidence.value || parsedEvidence.value.length === 0) return []
  // Get keys from first item, with preferred order
  const preferredOrder = ['package', 'name', 'version', 'description', 'type', 'severity', 'file', 'path', 'line']
  const allKeys = Object.keys(parsedEvidence.value[0])
  return allKeys.sort((a, b) => {
    const aIdx = preferredOrder.indexOf(a)
    const bIdx = preferredOrder.indexOf(b)
    if (aIdx === -1 && bIdx === -1) return 0
    if (aIdx === -1) return 1
    if (bIdx === -1) return -1
    return aIdx - bIdx
  })
})

function formatColumnHeader(col: string): string {
  return col.charAt(0).toUpperCase() + col.slice(1).replace(/_/g, ' ')
}

function getColumnClass(col: string): string {
  if (col === 'package' || col === 'name' || col === 'path' || col === 'file') return 'col-mono'
  if (col === 'version') return 'col-version'
  return ''
}

// Screenshot URL (assuming API serves screenshots)
const screenshotUrl = computed(() => {
  if (!props.screenshotPath) return ''
  // If it's already a full URL, use it
  if (props.screenshotPath.startsWith('http')) {
    return props.screenshotPath
  }
  // Otherwise, construct API URL
  return `/api/screenshots/${encodeURIComponent(props.screenshotPath)}`
})

function getCommandSeverity(type: string): string {
  const severityMap: Record<string, string> = {
    adb: 'success',
    frida: 'warning',
    bash: 'info',
    drozer: 'warning',
    objection: 'warning',
    android: 'success',
    ios: 'secondary',
  }
  return severityMap[type.toLowerCase()] || 'secondary'
}

function detectEvidenceLanguage(text: string): string {
  if (!text) return 'plaintext'
  const trimmed = text.trim()
  // Check if JSON
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
      (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      JSON.parse(trimmed)
      return 'json'
    } catch {
      // Not valid JSON
    }
  }
  // Check if XML
  if (trimmed.startsWith('<') && trimmed.includes('>')) {
    return 'xml'
  }
  return 'plaintext'
}

function isCodeEvidence(text: string): boolean {
  if (!text) return false
  const trimmed = text.trim()
  // Only use code block for JSON or XML
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
      (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      JSON.parse(trimmed)
      return true
    } catch {
      // Not valid JSON
    }
  }
  if (trimmed.startsWith('<') && trimmed.includes('>')) {
    return true
  }
  return false
}

function copyCommand(cmd: string) {
  navigator.clipboard.writeText(cmd)
  toast.add({
    severity: 'success',
    summary: 'Copied',
    detail: 'Command copied to clipboard',
    life: 2000,
  })
}

function copyAllCommands() {
  if (!props.commands) return
  const allCommands = props.commands.map((cmd) => cmd.command).join('\n')
  navigator.clipboard.writeText(allCommands)
  toast.add({
    severity: 'success',
    summary: 'Copied',
    detail: `${props.commands.length} commands copied to clipboard`,
    life: 2000,
  })
}

function copyFridaScript() {
  if (!props.fridaScript) return
  navigator.clipboard.writeText(props.fridaScript)
  toast.add({
    severity: 'success',
    summary: 'Copied',
    detail: 'Frida script copied to clipboard',
    life: 2000,
  })
}

function useFridaScript() {
  if (!props.fridaScript) return
  // Store script in localStorage and navigate to Frida view
  localStorage.setItem('pendingFridaScript', props.fridaScript)
  router.push('/frida').catch((err) => {
    console.warn('Navigation to Frida view failed:', err)
  })
}

function openLightbox() {
  showLightbox.value = true
}
</script>

<style scoped>
.poc-evidence {
  margin-top: 1rem;
}

.evidence-content {
  padding: 0;
  border-radius: 8px;
  overflow: hidden;
}

.evidence-text {
  margin: 0;
  padding: 1rem;
  white-space: pre-wrap;
  line-height: 1.7;
  font-family: 'Fira Code', 'Monaco', 'Consolas', monospace;
  font-size: 0.875rem;
  background: var(--surface-ground);
  color: var(--text-color);
  border-radius: 8px;
  border: 1px solid var(--surface-border);
}

.evidence-table-container {
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid var(--surface-border);
}

.evidence-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.evidence-table thead {
  background: var(--surface-100);
}

.evidence-table th {
  padding: 0.75rem 1rem;
  text-align: left;
  font-weight: 600;
  font-size: 0.75rem;
  text-transform: uppercase;
  color: var(--text-color-secondary);
  border-bottom: 1px solid var(--surface-border);
}

.evidence-table td {
  padding: 0.625rem 1rem;
  border-bottom: 1px solid var(--surface-border);
  color: var(--text-color);
}

.evidence-table tbody tr:last-child td {
  border-bottom: none;
}

.evidence-table tbody tr:hover {
  background: var(--surface-hover);
}

.evidence-table .col-mono {
  font-family: 'Fira Code', 'Monaco', 'Consolas', monospace;
  font-size: 0.8125rem;
}

.evidence-table .col-version {
  font-family: 'Fira Code', 'Monaco', 'Consolas', monospace;
  font-weight: 500;
  color: var(--primary-color);
}

.verification-content {
  padding: 0.5rem 0;
}

.verification-steps {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.verification-step {
  display: flex;
  align-items: flex-start;
  gap: 1rem;
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 8px;
}

.step-number {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: var(--primary-color);
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 0.85rem;
  flex-shrink: 0;
}

.step-text {
  flex: 1;
  line-height: 1.5;
}

.commands-content {
  display: flex;
  flex-direction: column;
  gap: 1rem;
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

.command-type-tag {
  font-size: 0.7rem;
  text-transform: uppercase;
  font-weight: 600;
}

.command-desc {
  color: #9ca3af;
  font-size: 0.8rem;
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

.copy-btn {
  color: #888 !important;
}

.copy-btn:hover {
  color: #fff !important;
}

.copy-all-section {
  display: flex;
  justify-content: flex-end;
  padding-top: 0.5rem;
}

.frida-content {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.frida-actions {
  display: flex;
  gap: 0.5rem;
  justify-content: flex-end;
}

.screenshot-content {
  display: flex;
  justify-content: center;
}

.screenshot-wrapper {
  position: relative;
  cursor: pointer;
  border-radius: 8px;
  overflow: hidden;
  max-width: 100%;
}

.screenshot-image {
  max-width: 100%;
  max-height: 400px;
  object-fit: contain;
  display: block;
}

.screenshot-overlay {
  position: absolute;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  color: white;
  opacity: 0;
  transition: opacity 0.2s;
}

.screenshot-wrapper:hover .screenshot-overlay {
  opacity: 1;
}

.screenshot-overlay i {
  font-size: 2rem;
}

.lightbox-content {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 200px;
}

.lightbox-image {
  max-width: 100%;
  max-height: 80vh;
  object-fit: contain;
}
</style>
