<template>
  <q-page padding>
    <div class="row items-center q-mb-md">
      <div class="text-h5">Postes</div>
      <q-space />
      <q-input
        v-model="search"
        dense
        outlined
        debounce="300"
        placeholder="Rechercher un poste…"
        @update:model-value="reload"
      >
        <template #append><q-icon name="search" /></template>
      </q-input>
    </div>

    <q-table
      :rows="rows"
      :columns="columns"
      row-key="id"
      :loading="loading"
      :rows-per-page-options="[25, 50, 100]"
    >
      <template #body-cell-is_up_to_date="props">
        <q-td :props="props">
          <q-badge :color="props.value ? 'positive' : 'negative'">
            {{ props.value ? 'À jour' : 'Non à jour' }}
          </q-badge>
        </q-td>
      </template>
    </q-table>
  </q-page>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue';
import type { QTableColumn } from 'quasar';
import { listMachines, type Machine } from 'src/services/machines';

const rows = ref<Machine[]>([]);
const loading = ref(false);
const search = ref('');

const columns: QTableColumn<Machine>[] = [
  { name: 'hostname', label: 'Nom', field: 'hostname', align: 'left', sortable: true },
  { name: 'domain', label: 'Domaine', field: 'domain', align: 'left', sortable: true },
  { name: 'os_version', label: 'OS', field: 'os_version', align: 'left' },
  { name: 'signature_version', label: 'Signatures', field: 'signature_version', align: 'left' },
  { name: 'is_up_to_date', label: 'État', field: 'is_up_to_date', align: 'center' },
  { name: 'last_seen', label: 'Vu le', field: 'last_seen', align: 'left', sortable: true },
];

async function reload() {
  loading.value = true;
  try {
    const params = search.value ? { search: search.value } : {};
    const data = await listMachines(params);
    rows.value = data.items;
  } finally {
    loading.value = false;
  }
}

onMounted(reload);
</script>
