<template>
  <div class="finding-detail-view">
    <div class="page-header">
      <div class="header-content">
        <Button icon="pi pi-arrow-left" class="p-button-text" @click="$router.back()" />
        <div>
          <div class="title-row">
            <Tag :value="finding?.severity" :severity="getSeverityColor(finding?.severity)" class="severity-tag" />
            <h1>{{ finding?.title || 'Finding Details' }}</h1>
          </div>
          <p class="text-secondary">{{ finding?.finding_id }}</p>
        </div>
      </div>
      <div class="header-actions">
        <Dropdown
          v-if="finding"
          :modelValue="finding.status"
          :options="statusOptions"
          @change="(e) => updateStatus(e.value)"
          placeholder="Status"
        />
      </div>
    </div>

    <div v-if="loading" class="loading-state">
      <ProgressSpinner />
    </div>

    <div v-else-if="finding" class="grid">
      <!-- Overview Card -->
      <div class="col-12">
        <div class="card overview-card">
          <div class="overview-grid">
            <div class="overview-item">
              <span class="overview-label">Category</span>
              <span class="overview-value">{{ finding.category || 'N/A' }}</span>
            </div>
            <div class="overview-item">
              <span class="overview-label">Tool</span>
              <Tag :value="finding.tool" severity="secondary" />
            </div>
            <div class="overview-item">
              <span class="overview-label">Platform</span>
              <Tag :value="finding.platform" :severity="finding.platform === 'android' ? 'success' : 'info'" />
            </div>
            <div v-if="finding.cwe_id" class="overview-item">
              <span class="overview-label">CWE</span>
              <a :href="`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`" target="_blank" class="cwe-link">
                {{ finding.cwe_id }}
              </a>
            </div>
            <div v-if="finding.cvss_score" class="overview-item">
              <span class="overview-label">CVSS</span>
              <span :class="['cvss-score', getCvssClass(finding.cvss_score)]">{{ finding.cvss_score }}</span>
            </div>
            <div v-if="finding.owasp_masvs_category" class="overview-item">
              <span class="overview-label">MASVS</span>
              <span class="overview-value">{{ finding.owasp_masvs_category }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Description -->
      <div class="col-12 lg:col-6">
        <div class="card">
          <h3><i class="pi pi-info-circle"></i> Description</h3>
          <div class="content-block">{{ finding.description }}</div>
        </div>
      </div>

      <!-- Impact -->
      <div class="col-12 lg:col-6">
        <div class="card">
          <h3><i class="pi pi-exclamation-triangle"></i> Impact</h3>
          <div class="content-block">{{ finding.impact }}</div>
        </div>
      </div>

      <!-- Location -->
      <div v-if="finding.file_path" class="col-12">
        <div class="card">
          <h3><i class="pi pi-file"></i> Location</h3>
          <div class="location-info">
            <div class="file-path">
              <i class="pi pi-folder"></i>
              {{ finding.file_path }}
              <span v-if="finding.line_number" class="line-number">:{{ finding.line_number }}</span>
            </div>
            <CodeBlock
              v-if="finding.code_snippet"
              :code="finding.code_snippet"
              :file-path="finding.file_path || undefined"
              :line-number="finding.line_number || undefined"
            />
          </div>
        </div>
      </div>

      <!-- PoC Evidence -->
      <div v-if="hasPocData" class="col-12">
        <div class="card poc-card">
          <h3><i class="pi pi-shield"></i> Proof of Concept</h3>
          <PocEvidence
            :evidence="finding.poc_evidence || undefined"
            :verification="finding.poc_verification || undefined"
            :commands="finding.poc_commands"
            :frida-script="finding.poc_frida_script || undefined"
            :screenshot-path="finding.poc_screenshot_path || undefined"
          />
        </div>
      </div>

      <!-- Remediation -->
      <div class="col-12">
        <div class="card remediation-card">
          <h3><i class="pi pi-check-circle"></i> Remediation</h3>
          <div class="remediation-content">{{ finding.remediation }}</div>
          <div v-if="finding.remediation_commands?.length" class="remediation-section">
            <h4>Fix Commands</h4>
            <div class="command-list">
              <div v-for="(cmd, index) in finding.remediation_commands" :key="index" class="command-item">
                <code>{{ cmd }}</code>
                <Button icon="pi pi-copy" class="p-button-sm p-button-text" @click="copyToClipboard(cmd)" />
              </div>
            </div>
          </div>
          <div v-if="finding.remediation_code && Object.keys(finding.remediation_code).length" class="remediation-section">
            <h4>Code Examples</h4>
            <TabView>
              <TabPanel v-for="(code, lang) in finding.remediation_code" :key="lang" :value="String(lang)" :header="String(lang)">
                <CodeBlock :code="String(code)" :language="String(lang)" />
              </TabPanel>
            </TabView>
          </div>
          <div v-if="finding.remediation_resources?.length" class="remediation-section">
            <h4>Resources</h4>
            <ul class="resource-list">
              <li v-for="(resource, index) in finding.remediation_resources" :key="index">
                <a :href="resource" target="_blank">{{ resource }}</a>
              </li>
            </ul>
          </div>
        </div>
      </div>

      <!-- OWASP Mapping -->
      <div v-if="finding.owasp_masvs_category || finding.owasp_mastg_test" class="col-12 lg:col-6">
        <div class="card">
          <h3><i class="pi pi-shield"></i> OWASP Mapping</h3>
          <div class="owasp-info">
            <div v-if="finding.owasp_masvs_category" class="owasp-item">
              <span class="owasp-label">MASVS Category</span>
              <span class="owasp-value">{{ finding.owasp_masvs_category }}</span>
            </div>
            <div v-if="finding.owasp_masvs_control" class="owasp-item">
              <span class="owasp-label">MASVS Control</span>
              <span class="owasp-value">{{ finding.owasp_masvs_control }}</span>
            </div>
            <div v-if="finding.owasp_mastg_test" class="owasp-item">
              <span class="owasp-label">MASTG Test</span>
              <a :href="`https://mas.owasp.org/MASTG/tests/${finding.owasp_mastg_test}`" target="_blank">
                {{ finding.owasp_mastg_test }}
              </a>
            </div>
          </div>
        </div>
      </div>

      <!-- Metadata -->
      <div class="col-12 lg:col-6">
        <div class="card">
          <h3><i class="pi pi-info"></i> Metadata</h3>
          <div class="metadata-list">
            <div class="metadata-item">
              <span class="metadata-label">First Seen</span>
              <span class="metadata-value">{{ formatDate(finding.first_seen) }}</span>
            </div>
            <div class="metadata-item">
              <span class="metadata-label">Last Seen</span>
              <span class="metadata-value">{{ formatDate(finding.last_seen) }}</span>
            </div>
            <div v-if="finding.tool_sources?.length" class="metadata-item">
              <span class="metadata-label">Sources</span>
              <span class="metadata-value">{{ finding.tool_sources.join(', ') }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useFindingsStore } from '@/stores/findings'
import { useToast } from 'primevue/usetoast'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Dropdown from 'primevue/dropdown'
import ProgressSpinner from 'primevue/progressspinner'
import TabView from 'primevue/tabview'
import TabPanel from 'primevue/tabpanel'
import Toast from 'primevue/toast'
import CodeBlock from '@/components/CodeBlock.vue'
import PocEvidence from '@/components/PocEvidence.vue'

const route = useRoute()
const router = useRouter()
const findingsStore = useFindingsStore()
const toast = useToast()

const loading = ref(true)

const finding = computed(() => findingsStore.currentFinding)
const statusOptions = ['open', 'confirmed', 'false_positive', 'accepted_risk', 'remediated']

// Check if there's any PoC data to display
const hasPocData = computed(() => {
  const f = finding.value
  if (!f) return false
  return (
    f.poc_evidence ||
    f.poc_verification ||
    (f.poc_commands && f.poc_commands.length > 0) ||
    f.poc_frida_script ||
    f.poc_screenshot_path
  )
})

function getSeverityColor(severity: string | undefined) {
  switch (severity) {
    case 'critical': return 'danger'
    case 'high': return 'danger'
    case 'medium': return 'warning'
    case 'low': return 'info'
    case 'info': return 'secondary'
    default: return 'secondary'
  }
}

function getCvssClass(score: number) {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  return 'low'
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleString()
}

async function updateStatus(status: string) {
  if (!finding.value) return
  try {
    await findingsStore.updateStatus(finding.value.finding_id, status)
    toast.add({ severity: 'success', summary: 'Updated', detail: 'Status updated', life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to update', life: 3000 })
  }
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text)
  toast.add({ severity: 'success', summary: 'Copied', detail: 'Copied to clipboard', life: 2000 })
}

onMounted(async () => {
  const findingId = route.params.id as string
  loading.value = true
  try {
    await findingsStore.fetchFinding(findingId)
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.finding-detail-view {
  padding: 1rem;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1.5rem;
}

.header-content {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
}

.title-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.severity-tag {
  font-size: 0.9rem;
}

.page-header h1 {
  margin: 0;
  font-size: 1.5rem;
}

.text-secondary {
  color: var(--text-color-secondary);
  margin: 0;
  font-family: monospace;
  font-size: 0.8rem;
}

.loading-state {
  display: flex;
  justify-content: center;
  padding: 3rem;
}

.card {
  background: var(--surface-card);
  border-radius: 8px;
  padding: 1.25rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  height: 100%;
}

.card h3 {
  margin: 0 0 1rem;
  font-size: 1.1rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.card h3 i {
  color: var(--primary-color);
}

.card h4 {
  margin: 1rem 0 0.5rem;
  font-size: 0.95rem;
  color: var(--text-color-secondary);
}

.overview-card {
  background: linear-gradient(135deg, var(--surface-card), var(--surface-ground));
}

.overview-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 2rem;
}

.overview-item {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.overview-label {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
}

.overview-value {
  font-weight: 600;
}

.cwe-link {
  color: var(--primary-color);
  text-decoration: none;
  font-weight: 600;
}

.cvss-score {
  font-weight: 700;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  color: white;
}

.cvss-score.critical { background: #dc3545; }
.cvss-score.high { background: #fd7e14; }
.cvss-score.medium { background: #ffc107; color: #212529; }
.cvss-score.low { background: #28a745; }

.content-block {
  line-height: 1.6;
  white-space: pre-wrap;
}

.location-info {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.file-path {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-family: monospace;
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 4px;
}

.line-number {
  color: var(--primary-color);
  font-weight: 600;
}

.code-snippet {
  background: #1e1e1e;
  border-radius: 4px;
  overflow-x: auto;
}

.code-snippet pre {
  margin: 0;
  padding: 1rem;
}

.code-snippet code {
  color: #d4d4d4;
  font-size: 0.85rem;
}

.poc-card {
  border-left: 4px solid var(--primary-color);
}

.poc-section {
  margin-bottom: 1.5rem;
}

.poc-content {
  padding: 1rem;
  background: var(--surface-ground);
  border-radius: 4px;
  white-space: pre-wrap;
}

.command-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.command-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.75rem;
  background: #1e1e1e;
  border-radius: 4px;
}

.command-item code {
  color: #4ec9b0;
  font-size: 0.85rem;
}

.frida-script {
  position: relative;
}

.frida-script pre {
  margin: 0;
  padding: 1rem;
  background: #1e1e1e;
  border-radius: 4px;
  overflow-x: auto;
  margin-bottom: 0.5rem;
}

.frida-script code {
  color: #d4d4d4;
  font-size: 0.85rem;
}

.remediation-card {
  border-left: 4px solid #28a745;
}

.remediation-content {
  line-height: 1.6;
  white-space: pre-wrap;
  margin-bottom: 1rem;
}

.remediation-section {
  margin-top: 1.5rem;
}

.resource-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.resource-list li {
  padding: 0.5rem 0;
  border-bottom: 1px solid var(--surface-border);
}

.resource-list a {
  color: var(--primary-color);
  text-decoration: none;
  word-break: break-all;
}

.owasp-info {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.owasp-item {
  display: flex;
  justify-content: space-between;
  padding: 0.5rem;
  background: var(--surface-ground);
  border-radius: 4px;
}

.owasp-label {
  color: var(--text-color-secondary);
}

.owasp-value {
  font-weight: 500;
}

.metadata-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.metadata-item {
  display: flex;
  justify-content: space-between;
  padding: 0.5rem;
  background: var(--surface-ground);
  border-radius: 4px;
}

.metadata-label {
  color: var(--text-color-secondary);
}

.metadata-value {
  font-weight: 500;
}
</style>
