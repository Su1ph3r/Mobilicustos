<template>
  <div v-if="finding.poc_verification" class="verification-command">
    <h4>
      <i class="pi pi-terminal" />
      Verification Command
    </h4>
    <div class="command-block">
      <pre class="code-block">{{ processedCommand }}</pre>
      <Button
        icon="pi pi-copy"
        class="p-button-text p-button-sm copy-btn"
        @click="copyCommand"
        v-tooltip.top="copied ? 'Copied!' : 'Copy to clipboard'"
        :class="{ copied }"
      />
    </div>
    <p v-if="hasPlaceholders" class="placeholder-hint">
      <i class="pi pi-info-circle" />
      Replace placeholders with actual values before running
    </p>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import Button from 'primevue/button'
import type { Finding } from '@/stores/findings'

const props = defineProps<{
  finding: Finding
}>()

const copied = ref(false)

// Process command to replace common placeholders with finding data
const processedCommand = computed(() => {
  let cmd = props.finding.poc_verification || ''

  // Replace common placeholders with null guards
  const appId = props.finding.app_id
  if (appId) {
    // Extract package name from app_id (format: package.name-version)
    const packageName = appId.includes('-') ? appId.split('-')[0] : appId
    cmd = cmd.replace(/\{package_name\}/g, packageName)
    cmd = cmd.replace(/\{app_id\}/g, appId)
  }
  const filePath = props.finding.file_path
  if (filePath) {
    cmd = cmd.replace(/\{file_path\}/g, filePath)
  }
  const findingId = props.finding.finding_id
  if (findingId) {
    cmd = cmd.replace(/\{finding_id\}/g, findingId)
  }

  return cmd
})

// Check if there are remaining placeholders
const hasPlaceholders = computed(() => {
  return /\{[a-zA-Z_]+\}/.test(processedCommand.value)
})

const copyCommand = async () => {
  try {
    await navigator.clipboard.writeText(processedCommand.value)
    copied.value = true
    setTimeout(() => {
      copied.value = false
    }, 2000)
  } catch {
    console.error('Failed to copy command')
  }
}
</script>

<style scoped>
.verification-command {
  margin-bottom: var(--spacing-lg);
}

.verification-command h4 {
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

.verification-command h4 i {
  color: var(--accent-primary, var(--primary-color));
  font-size: 0.875rem;
}

.command-block {
  position: relative;
  background: #1e293b;
  border-radius: var(--radius-sm);
  overflow: hidden;
}

.code-block {
  background: transparent;
  color: #e2e8f0;
  padding: var(--spacing-md);
  padding-right: 3rem;
  font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 0.8125rem;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0;
}

.copy-btn {
  position: absolute;
  top: var(--spacing-xs);
  right: var(--spacing-xs);
  color: #94a3b8 !important;
  background: transparent !important;
  border: none !important;
}

.copy-btn:hover {
  color: #e2e8f0 !important;
  background: rgba(255, 255, 255, 0.1) !important;
}

.copy-btn.copied {
  color: #22c55e !important;
}

.placeholder-hint {
  margin-top: var(--spacing-sm);
  font-size: 0.75rem;
  color: var(--text-secondary, var(--text-color-secondary));
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
}

.placeholder-hint i {
  color: var(--severity-medium);
}
</style>
