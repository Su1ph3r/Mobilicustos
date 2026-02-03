<template>
  <div class="poc-evidence">
    <TabView>
      <!-- Evidence Tab -->
      <TabPanel v-if="evidence" value="evidence" header="Evidence">
        <div class="evidence-content">
          <div class="evidence-text">{{ evidence }}</div>
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
          <div v-for="(cmd, index) in commands" :key="index" class="command-item">
            <code class="command-text">{{ cmd }}</code>
            <Button
              icon="pi pi-copy"
              class="p-button-sm p-button-text"
              v-tooltip.top="'Copy command'"
              @click="copyCommand(cmd)"
            />
          </div>
          <div class="copy-all-section">
            <Button
              label="Copy All"
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
import CodeBlock from './CodeBlock.vue'

const props = defineProps<{
  evidence?: string
  verification?: string
  commands?: string[]
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
  const allCommands = props.commands.join('\n')
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
  padding: 1rem;
  background: var(--surface-ground);
  border-radius: 8px;
}

.evidence-text {
  white-space: pre-wrap;
  line-height: 1.6;
  font-family: monospace;
  font-size: 0.9rem;
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
  gap: 0.5rem;
}

.command-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.75rem 1rem;
  background: #1e1e1e;
  border-radius: 6px;
}

.command-text {
  color: #4ec9b0;
  font-size: 0.85rem;
  font-family: 'Fira Code', 'Monaco', monospace;
  word-break: break-all;
}

.copy-all-section {
  display: flex;
  justify-content: flex-end;
  margin-top: 0.5rem;
  padding-top: 0.5rem;
  border-top: 1px solid var(--surface-border);
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
