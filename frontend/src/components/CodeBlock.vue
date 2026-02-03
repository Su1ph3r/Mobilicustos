<template>
  <div class="code-block">
    <div class="code-header">
      <span class="language-badge">{{ displayLanguage }}</span>
      <div class="code-actions">
        <span v-if="filePath" class="file-path">{{ filePath }}</span>
        <Button
          icon="pi pi-copy"
          class="p-button-sm p-button-text"
          v-tooltip.top="'Copy to clipboard'"
          @click="copyCode"
        />
      </div>
    </div>
    <pre class="code-content"><code :class="`language-${language}`" v-html="highlightedCode"></code></pre>
    <div v-if="lineNumber" class="line-indicator">
      Line {{ lineNumber }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import { useToast } from 'primevue/usetoast'

const props = defineProps<{
  code: string
  language?: string
  filePath?: string
  lineNumber?: number
}>()

const toast = useToast()
const hljs = ref<any>(null)

// Language detection based on file extension or explicit language
const language = computed(() => {
  if (props.language) return props.language

  if (props.filePath) {
    const ext = props.filePath.split('.').pop()?.toLowerCase()
    const extMap: Record<string, string> = {
      'java': 'java',
      'kt': 'kotlin',
      'swift': 'swift',
      'm': 'objectivec',
      'js': 'javascript',
      'ts': 'typescript',
      'json': 'json',
      'xml': 'xml',
      'plist': 'xml',
      'py': 'python',
      'sh': 'bash',
      'smali': 'smali',
      'dart': 'dart',
    }
    return extMap[ext || ''] || 'plaintext'
  }

  // Auto-detect from content
  const code = props.code.toLowerCase()
  if (code.includes('java.') || code.includes('public class')) return 'java'
  if (code.includes('<key>') || code.includes('<?xml')) return 'xml'
  if (code.includes('func ') && code.includes('->')) return 'swift'
  if (code.includes('objc.') || code.includes('@interface')) return 'objectivec'
  if (code.includes('function') || code.includes('const ')) return 'javascript'

  return 'plaintext'
})

const displayLanguage = computed(() => {
  const langNames: Record<string, string> = {
    'java': 'Java',
    'kotlin': 'Kotlin',
    'swift': 'Swift',
    'objectivec': 'Objective-C',
    'javascript': 'JavaScript',
    'typescript': 'TypeScript',
    'json': 'JSON',
    'xml': 'XML',
    'python': 'Python',
    'bash': 'Bash',
    'smali': 'Smali',
    'dart': 'Dart',
    'plaintext': 'Text',
  }
  return langNames[language.value] || language.value
})

const highlightedCode = computed(() => {
  if (!props.code) return ''

  // If highlight.js is loaded, use it
  if (hljs.value) {
    try {
      const result = hljs.value.highlight(props.code, {
        language: language.value,
        ignoreIllegals: true,
      })
      return result.value
    } catch {
      // Fallback to escaped HTML
      return escapeHtml(props.code)
    }
  }

  // Fallback: escape HTML and apply basic styling
  return escapeHtml(props.code)
})

function escapeHtml(text: string): string {
  const div = document.createElement('div')
  div.textContent = text
  return div.innerHTML
}

function copyCode() {
  navigator.clipboard.writeText(props.code)
  toast.add({
    severity: 'success',
    summary: 'Copied',
    detail: 'Code copied to clipboard',
    life: 2000,
  })
}

onMounted(async () => {
  // Dynamically load highlight.js
  try {
    const hljsModule = await import('highlight.js/lib/core')
    hljs.value = hljsModule.default

    // Register common languages individually to avoid single failure breaking all
    const languages = [
      { name: 'java', path: 'highlight.js/lib/languages/java' },
      { name: 'xml', path: 'highlight.js/lib/languages/xml' },
      { name: 'javascript', path: 'highlight.js/lib/languages/javascript' },
      { name: 'swift', path: 'highlight.js/lib/languages/swift' },
      { name: 'bash', path: 'highlight.js/lib/languages/bash' },
      { name: 'json', path: 'highlight.js/lib/languages/json' },
    ]

    for (const lang of languages) {
      try {
        const module = await import(/* @vite-ignore */ lang.path)
        hljs.value.registerLanguage(lang.name, module.default)
      } catch {
        console.warn(`Failed to load language: ${lang.name}`)
      }
    }
  } catch (e) {
    console.warn('highlight.js not available, using fallback')
  }
})
</script>

<style scoped>
.code-block {
  border-radius: 8px;
  overflow: hidden;
  background: #1e1e1e;
  font-family: 'Fira Code', 'Monaco', 'Consolas', monospace;
}

.code-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem 1rem;
  background: #2d2d2d;
  border-bottom: 1px solid #3d3d3d;
}

.language-badge {
  font-size: 0.75rem;
  font-weight: 600;
  color: #888;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.code-actions {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.file-path {
  font-size: 0.75rem;
  color: #888;
  font-family: monospace;
}

.code-content {
  margin: 0;
  padding: 1rem;
  overflow-x: auto;
  font-size: 0.85rem;
  line-height: 1.5;
}

.code-content code {
  color: #d4d4d4;
  background: transparent;
}

.line-indicator {
  padding: 0.5rem 1rem;
  font-size: 0.75rem;
  color: #888;
  background: #2d2d2d;
  border-top: 1px solid #3d3d3d;
}

/* Syntax highlighting colors */
:deep(.hljs-keyword) { color: #569cd6; }
:deep(.hljs-string) { color: #ce9178; }
:deep(.hljs-comment) { color: #6a9955; }
:deep(.hljs-number) { color: #b5cea8; }
:deep(.hljs-function) { color: #dcdcaa; }
:deep(.hljs-class) { color: #4ec9b0; }
:deep(.hljs-variable) { color: #9cdcfe; }
:deep(.hljs-attr) { color: #9cdcfe; }
:deep(.hljs-tag) { color: #569cd6; }
:deep(.hljs-name) { color: #569cd6; }
:deep(.hljs-attribute) { color: #9cdcfe; }
:deep(.hljs-built_in) { color: #4ec9b0; }
</style>
