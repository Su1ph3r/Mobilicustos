<template>
  <div class="finding-detail">
    <!-- Tool Sources Section -->
    <div v-if="finding.tool_sources && finding.tool_sources.length > 0" class="detail-section tools-section">
      <h4>
        <i class="pi pi-search" />
        Detected By
      </h4>
      <div class="tool-badges">
        <span v-for="tool in finding.tool_sources" :key="tool" class="tool-badge">
          {{ formatToolName(tool) }}
        </span>
      </div>
    </div>

    <!-- Description Section -->
    <div class="detail-section">
      <h4>
        <i class="pi pi-file-edit" />
        Description
      </h4>
      <p class="description">
        {{ finding.description || 'No description available' }}
      </p>
    </div>

    <!-- Location Details -->
    <div class="detail-section">
      <h4>
        <i class="pi pi-map-marker" />
        Location Details
      </h4>
      <div class="detail-grid">
        <div class="detail-item">
          <span class="label">File Path</span>
          <span class="value code">{{ finding.file_path || 'N/A' }}</span>
        </div>
        <div class="detail-item">
          <span class="label">Line Number</span>
          <span class="value">{{ finding.line_number || 'N/A' }}</span>
        </div>
        <div class="detail-item">
          <span class="label">Category</span>
          <span class="value">{{ finding.category || 'N/A' }}</span>
        </div>
        <div class="detail-item">
          <span class="label">Platform</span>
          <span class="value">{{ finding.platform || 'N/A' }}</span>
        </div>
        <div class="detail-item">
          <span class="label">Tool</span>
          <span class="value">{{ formatToolName(finding.tool) }}</span>
        </div>
        <div class="detail-item">
          <span class="label">CWE</span>
          <a
            v-if="finding.cwe_id"
            :href="`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`"
            target="_blank"
            class="value link"
          >
            {{ finding.cwe_id }}
          </a>
          <span v-else class="value">N/A</span>
        </div>
      </div>
    </div>

    <!-- Code Snippet Section -->
    <div v-if="finding.code_snippet" class="detail-section">
      <h4>
        <i class="pi pi-code" />
        Code Snippet
      </h4>
      <pre class="code-block">{{ finding.code_snippet }}</pre>
    </div>

    <!-- PoC Evidence Section -->
    <div v-if="finding.poc_evidence || finding.poc_frida_script" class="detail-section">
      <h4>
        <i class="pi pi-eye" />
        Proof of Concept
      </h4>
      <div v-if="finding.poc_evidence" class="poc-content">
        <p>{{ finding.poc_evidence }}</p>
      </div>
      <div v-if="finding.poc_frida_script" class="poc-script">
        <h5>Frida Script</h5>
        <pre class="code-block frida">{{ finding.poc_frida_script }}</pre>
      </div>
      <div v-if="finding.poc_commands && finding.poc_commands.length > 0" class="poc-commands">
        <h5>PoC Commands</h5>
        <pre class="code-block">{{ finding.poc_commands.join('\n') }}</pre>
      </div>
    </div>

    <!-- Impact Section -->
    <div v-if="finding.impact" class="detail-section">
      <h4>
        <i class="pi pi-exclamation-triangle" />
        Impact
      </h4>
      <p class="description">{{ finding.impact }}</p>
    </div>

    <!-- Remediation Section -->
    <div class="detail-section">
      <h4>
        <i class="pi pi-wrench" />
        Remediation
      </h4>
      <p class="description">{{ finding.remediation || 'No remediation guidance available' }}</p>
      <div v-if="finding.owasp_masvs_control" class="masvs-reference">
        <span class="label">MASVS Control:</span>
        <span class="value">{{ finding.owasp_masvs_control }}</span>
      </div>
      <div v-if="finding.owasp_mastg_test" class="masvs-reference">
        <span class="label">MASTG Test:</span>
        <span class="value">{{ finding.owasp_mastg_test }}</span>
      </div>
      <div v-if="finding.remediation_resources && finding.remediation_resources.length > 0" class="resources-list">
        <h5>Resources</h5>
        <ul>
          <li v-for="(resource, idx) in finding.remediation_resources" :key="idx">
            <a :href="resource" target="_blank" rel="noopener">{{ resource }}</a>
          </li>
        </ul>
      </div>
    </div>

    <!-- Metadata Section -->
    <div class="detail-section metadata-section">
      <h4>
        <i class="pi pi-info-circle" />
        Metadata
      </h4>
      <div class="detail-grid">
        <div class="detail-item">
          <span class="label">Finding ID</span>
          <span class="value code small">{{ finding.finding_id }}</span>
        </div>
        <div class="detail-item">
          <span class="label">First Seen</span>
          <span class="value">{{ formatDate(finding.first_seen) }}</span>
        </div>
        <div class="detail-item">
          <span class="label">Last Seen</span>
          <span class="value">{{ formatDate(finding.last_seen) }}</span>
        </div>
        <div v-if="finding.canonical_id" class="detail-item">
          <span class="label">Canonical ID</span>
          <span class="value code small">{{ finding.canonical_id }}</span>
        </div>
        <div v-if="finding.cvss_score" class="detail-item">
          <span class="label">CVSS Score</span>
          <span class="value cvss" :class="getCvssSeverity(finding.cvss_score)">
            {{ finding.cvss_score }}
          </span>
        </div>
        <div v-if="finding.risk_score" class="detail-item">
          <span class="label">Risk Score</span>
          <span class="value">{{ finding.risk_score }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { Finding } from '@/stores/findings'

defineProps<{
  finding: Finding
}>()

const formatDate = (dateStr: string) => {
  if (!dateStr) return 'N/A'
  return new Date(dateStr).toLocaleString()
}

const formatToolName = (tool: string) => {
  if (!tool) return 'Unknown'
  return tool.charAt(0).toUpperCase() + tool.slice(1).replace(/_/g, ' ')
}

const getCvssSeverity = (score: number): string => {
  if (score >= 9.0) return 'critical'
  if (score >= 7.0) return 'high'
  if (score >= 4.0) return 'medium'
  if (score >= 0.1) return 'low'
  return 'info'
}
</script>

<style scoped>
.finding-detail {
  padding: var(--spacing-lg);
  background: var(--bg-secondary, var(--surface-card));
  border-radius: var(--radius-md);
}

.detail-section {
  margin-bottom: var(--spacing-xl);
}

.detail-section:last-child {
  margin-bottom: 0;
}

.detail-section h4 {
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

.detail-section h4 i {
  color: var(--accent-primary, var(--primary-color));
  font-size: 0.875rem;
}

.detail-section h5 {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-secondary, var(--text-color-secondary));
  margin: var(--spacing-md) 0 var(--spacing-sm);
  text-transform: uppercase;
}

.tools-section .tool-badges {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-sm);
}

.tool-badge {
  display: inline-flex;
  align-items: center;
  padding: 6px 12px;
  border-radius: var(--radius-md);
  font-size: 0.8125rem;
  font-weight: 500;
  background: var(--accent-primary-bg);
  color: var(--accent-primary, var(--primary-color));
  border: 1px solid rgba(99, 102, 241, 0.2);
}

.description {
  color: var(--text-primary, var(--text-color));
  line-height: 1.7;
  font-size: 0.9375rem;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: var(--spacing-md);
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: var(--spacing-sm);
  background: var(--bg-tertiary, var(--surface-ground));
  border-radius: var(--radius-sm);
}

.detail-item .label {
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--text-tertiary, var(--text-color-secondary));
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.detail-item .value {
  color: var(--text-primary, var(--text-color));
  font-size: 0.875rem;
  word-break: break-word;
}

.detail-item .value.code {
  font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 0.8125rem;
  background: var(--bg-card, var(--surface-card));
  padding: 4px 8px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-color);
}

.detail-item .value.code.small {
  font-size: 0.75rem;
}

.detail-item .value.link {
  color: var(--accent-primary, var(--primary-color));
  text-decoration: none;
}

.detail-item .value.link:hover {
  text-decoration: underline;
}

.detail-item .value.cvss {
  font-weight: 600;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
}

.detail-item .value.cvss.critical {
  background: var(--severity-critical-bg);
  color: var(--severity-critical);
}

.detail-item .value.cvss.high {
  background: var(--severity-high-bg);
  color: var(--severity-high);
}

.detail-item .value.cvss.medium {
  background: var(--severity-medium-bg);
  color: var(--severity-medium);
}

.detail-item .value.cvss.low {
  background: var(--severity-low-bg);
  color: var(--severity-low);
}

.code-block {
  background: #1e293b;
  color: #e2e8f0;
  padding: var(--spacing-md);
  border-radius: var(--radius-sm);
  font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 0.8125rem;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0;
}

.code-block.frida {
  background: #1a1a2e;
  border-left: 3px solid var(--accent-primary, var(--primary-color));
}

.poc-content {
  padding: var(--spacing-md);
  background: var(--bg-tertiary, var(--surface-ground));
  border-radius: var(--radius-sm);
  margin-bottom: var(--spacing-md);
}

.poc-content p {
  margin: 0;
  color: var(--text-primary, var(--text-color));
}

.masvs-reference {
  display: flex;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) 0;
  font-size: 0.875rem;
}

.masvs-reference .label {
  font-weight: 600;
  color: var(--text-secondary, var(--text-color-secondary));
}

.masvs-reference .value {
  color: var(--accent-primary, var(--primary-color));
}

.resources-list {
  margin-top: var(--spacing-md);
}

.resources-list ul {
  margin: 0;
  padding-left: var(--spacing-lg);
}

.resources-list li {
  margin-bottom: var(--spacing-xs);
}

.resources-list a {
  color: var(--accent-primary, var(--primary-color));
  text-decoration: none;
  font-size: 0.875rem;
}

.resources-list a:hover {
  text-decoration: underline;
}

.metadata-section {
  opacity: 0.9;
}
</style>
