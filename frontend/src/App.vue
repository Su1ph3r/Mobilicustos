<script setup lang="ts">
import { RouterView } from 'vue-router'
import Toast from 'primevue/toast'
import ConfirmDialog from 'primevue/confirmdialog'
import AppLayout from './components/AppLayout.vue'
</script>

<template>
  <Toast />
  <ConfirmDialog />
  <AppLayout>
    <RouterView />
  </AppLayout>
</template>

<style>
html, body, #app {
  height: 100%;
  margin: 0;
  padding: 0;
}
</style>
