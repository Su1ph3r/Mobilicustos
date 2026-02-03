<script setup lang="ts">
import Dialog from 'primevue/dialog'

defineProps<{
  visible: boolean
}>()

const emit = defineEmits<{
  (e: 'update:visible', value: boolean): void
}>()

const shortcutGroups = [
  {
    title: 'Navigation',
    shortcuts: [
      { keys: ['Alt', 'D'], description: 'Go to Dashboard' },
      { keys: ['Alt', 'A'], description: 'Go to Apps' },
      { keys: ['Alt', 'S'], description: 'Go to Scans' },
      { keys: ['Alt', 'F'], description: 'Go to Findings' },
      { keys: ['Alt', 'V'], description: 'Go to Devices' },
      { keys: ['Alt', 'R'], description: 'Go to Frida' },
      { keys: ['Alt', 'C'], description: 'Go to Compliance' },
      { keys: ['Alt', 'P'], description: 'Go to Attack Paths' },
      { keys: ['Alt', 'K'], description: 'Go to Secrets' },
    ]
  },
  {
    title: 'Actions',
    shortcuts: [
      { keys: ['Ctrl', '/'], description: 'Focus search' },
      { keys: ['Ctrl', 'N'], description: 'New item' },
      { keys: ['Esc'], description: 'Close dialog' },
      { keys: ['?'], description: 'Show this help' },
    ]
  },
  {
    title: 'List Navigation',
    shortcuts: [
      { keys: ['↓', 'J'], description: 'Move down' },
      { keys: ['↑', 'K'], description: 'Move up' },
      { keys: ['Home'], description: 'Go to first item' },
      { keys: ['End'], description: 'Go to last item' },
      { keys: ['Enter'], description: 'Select item' },
    ]
  }
]
</script>

<template>
  <Dialog
    :visible="visible"
    @update:visible="emit('update:visible', $event)"
    header="Keyboard Shortcuts"
    :modal="true"
    :style="{ width: '500px' }"
    :draggable="false"
    class="keyboard-shortcuts-dialog"
  >
    <div class="shortcuts-container">
      <div
        v-for="group in shortcutGroups"
        :key="group.title"
        class="shortcut-group"
      >
        <h4 class="group-title">{{ group.title }}</h4>
        <div class="shortcut-list">
          <div
            v-for="shortcut in group.shortcuts"
            :key="shortcut.description"
            class="shortcut-item"
          >
            <div class="shortcut-keys">
              <kbd v-for="key in shortcut.keys" :key="key">{{ key }}</kbd>
            </div>
            <span class="shortcut-description">{{ shortcut.description }}</span>
          </div>
        </div>
      </div>
    </div>
  </Dialog>
</template>

<style scoped>
.shortcuts-container {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.shortcut-group {
  border-bottom: 1px solid var(--surface-border);
  padding-bottom: 1rem;
}

.shortcut-group:last-child {
  border-bottom: none;
  padding-bottom: 0;
}

.group-title {
  margin: 0 0 0.75rem 0;
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--text-color-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.shortcut-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.shortcut-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.25rem 0;
}

.shortcut-keys {
  display: flex;
  gap: 0.25rem;
}

kbd {
  display: inline-block;
  padding: 0.25rem 0.5rem;
  font-family: monospace;
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--text-color);
  background: var(--surface-100);
  border: 1px solid var(--surface-border);
  border-radius: 4px;
  box-shadow: 0 1px 0 var(--surface-border);
}

.shortcut-description {
  font-size: 0.875rem;
  color: var(--text-color);
}

/* Responsive */
@media (max-width: 576px) {
  :deep(.p-dialog) {
    width: 95vw !important;
    margin: 0.5rem;
  }
}
</style>
