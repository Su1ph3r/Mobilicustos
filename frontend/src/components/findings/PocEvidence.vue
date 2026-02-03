<template>
  <div v-if="hasPocData" class="poc-evidence">
    <h4>
      <i class="pi pi-eye" />
      Proof of Concept
    </h4>

    <!-- Evidence Text -->
    <div v-if="finding.poc_evidence" class="poc-section">
      <h5>Evidence</h5>
      <div class="evidence-content">
        <pre v-if="isJsonEvidence" class="code-block json">{{ formattedEvidence }}</pre>
        <p v-else class="evidence-text">{{ finding.poc_evidence }}</p>
      </div>
    </div>

    <!-- Screenshot -->
    <div v-if="finding.poc_screenshot_path" class="poc-section">
      <h5>Screenshot</h5>
      <div class="screenshot-container">
        <img :src="finding.poc_screenshot_path" alt="PoC Screenshot" class="screenshot" />
      </div>
    </div>

    <!-- PoC Commands -->
    <div v-if="finding.poc_commands && finding.poc_commands.length > 0" class="poc-section">
      <h5>Commands</h5>
      <div class="commands-list">
        <div v-for="(cmd, idx) in finding.poc_commands" :key="idx" class="command-item">
          <div class="command-header">
            <span class="command-type" :class="getTypeClass(cmd.type)">{{ cmd.type }}</span>
            <span v-if="cmd.description" class="command-description">{{ cmd.description }}</span>
            <Button
              icon="pi pi-copy"
              class="p-button-text p-button-sm copy-btn"
              @click="copyCommand(cmd.command, idx)"
              v-tooltip.top="copiedIdx === idx ? 'Copied!' : 'Copy'"
            />
          </div>
          <pre class="code-block command">{{ cmd.command }}</pre>
        </div>
      </div>
    </div>

    <!-- Frida Script -->
    <div v-if="finding.poc_frida_script" class="poc-section">
      <h5>
        <span>Frida Script</span>
        <Button
          icon="pi pi-copy"
          class="p-button-text p-button-sm"
          @click="copyFridaScript"
          v-tooltip.top="fridaCopied ? 'Copied!' : 'Copy script'"
        />
      </h5>
      <pre class="code-block frida">{{ finding.poc_frida_script }}</pre>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import Button from 'primevue/button'
import type { Finding } from '@/stores/findings'

const props = defineProps<{
  finding: Finding
}>()

const copiedIdx = ref<number | null>(null)
const fridaCopied = ref(false)

const hasPocData = computed(() => {
  return (
    props.finding.poc_evidence ||
    props.finding.poc_screenshot_path ||
    (props.finding.poc_commands && props.finding.poc_commands.length > 0) ||
    props.finding.poc_frida_script
  )
})

const isJsonEvidence = computed(() => {
  if (!props.finding.poc_evidence) return false
  try {
    JSON.parse(props.finding.poc_evidence)
    return true
  } catch {
    return false
  }
})

const formattedEvidence = computed(() => {
  if (!isJsonEvidence.value) return props.finding.poc_evidence
  try {
    return JSON.stringify(JSON.parse(props.finding.poc_evidence!), null, 2)
  } catch {
    return props.finding.poc_evidence
  }
})

const getTypeClass = (type: string): string => {
  const typeMap: Record<string, string> = {
    adb: 'type-adb',
    frida: 'type-frida',
    bash: 'type-bash',
    drozer: 'type-drozer',
    objection: 'type-objection',
    android: 'type-android',
    ios: 'type-ios',
  }
  return typeMap[type.toLowerCase()] || 'type-default'
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

const copyFridaScript = async () => {
  if (!props.finding.poc_frida_script) return
  try {
    await navigator.clipboard.writeText(props.finding.poc_frida_script)
    fridaCopied.value = true
    setTimeout(() => {
      fridaCopied.value = false
    }, 2000)
  } catch {
    console.error('Failed to copy script')
  }
}
</script>

<style scoped>
.poc-evidence {
  margin-bottom: var(--spacing-lg);
}

.poc-evidence h4 {
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

.poc-evidence h4 i {
  color: var(--accent-primary, var(--primary-color));
  font-size: 0.875rem;
}

.poc-section {
  margin-bottom: var(--spacing-lg);
}

.poc-section:last-child {
  margin-bottom: 0;
}

.poc-section h5 {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-secondary, var(--text-color-secondary));
  margin-bottom: var(--spacing-sm);
  text-transform: uppercase;
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.evidence-content {
  background: var(--bg-tertiary, var(--surface-ground));
  border-radius: var(--radius-sm);
  padding: var(--spacing-md);
}

.evidence-text {
  margin: 0;
  color: var(--text-primary, var(--text-color));
  line-height: 1.6;
  font-size: 0.875rem;
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

.code-block.json {
  background: #1a2e3b;
}

.code-block.frida {
  background: #1a1a2e;
  border-left: 3px solid var(--accent-primary, var(--primary-color));
}

.code-block.command {
  background: #0f172a;
  padding: var(--spacing-sm) var(--spacing-md);
}

.screenshot-container {
  max-width: 100%;
  overflow: hidden;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-color);
}

.screenshot {
  max-width: 100%;
  height: auto;
  display: block;
}

.commands-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.command-item {
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  overflow: hidden;
}

.command-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--bg-tertiary, var(--surface-ground));
  border-bottom: 1px solid var(--border-color);
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

.type-drozer {
  background: rgba(249, 115, 22, 0.15);
  color: #f97316;
}

.type-objection {
  background: rgba(236, 72, 153, 0.15);
  color: #ec4899;
}

.type-android {
  background: rgba(163, 230, 53, 0.15);
  color: #a3e635;
}

.type-ios {
  background: rgba(156, 163, 175, 0.15);
  color: #9ca3af;
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
</style>
