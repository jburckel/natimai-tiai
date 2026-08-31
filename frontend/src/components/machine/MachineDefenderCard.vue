<template>
  <MachineInfoCard title="État Defender" :caption="caption" :rows="rows" />
</template>

<script setup lang="ts">
import { computed } from 'vue';
import MachineInfoCard from './MachineInfoCard.vue';
import type { InfoRow } from './types';
import type { MachineDetail } from 'src/services/machines';
import { boolLabel, formatDateTime, runningModeLabel } from 'src/utils/format';

const props = defineProps<{ machine: MachineDetail }>();

const caption = computed(() =>
  props.machine.av_product_is_defender
    ? "Defender est l'antivirus enregistré au Security Center de Windows."
    : undefined,
);

const rows = computed<InfoRow[]>(() => {
  const m = props.machine;
  return [
    { label: 'Defender actif', value: boolLabel(m.av_enabled) },
    { label: 'Protection temps réel', value: boolLabel(m.rtp_enabled) },
    // Placed right under the two flags above: this is the row that explains
    // them reading "Non" on a machine that is in fact protected, a
    // third-party antivirus having pushed Defender into passive mode.
    { label: "Mode d'exécution", value: runningModeLabel(m.running_mode) },
    { label: 'À jour', value: boolLabel(m.is_up_to_date) },
    { label: 'Version signatures', value: m.signature_version ?? '—' },
    { label: 'Signatures à jour le', value: formatDateTime(m.signature_last_updated) },
    { label: 'Âge signatures (j)', value: m.signature_age_days ?? '—' },
    { label: 'Dernier scan rapide', value: formatDateTime(m.last_quick_scan) },
    { label: 'Dernier scan complet', value: formatDateTime(m.last_full_scan) },
  ];
});
</script>
