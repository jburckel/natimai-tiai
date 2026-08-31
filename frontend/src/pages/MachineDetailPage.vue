<template>
  <q-page padding>
    <div class="row items-center q-mb-md">
      <q-btn
        flat
        dense
        round
        icon="arrow_back"
        :to="{ name: 'machines', query: backQuery }"
        class="q-mr-sm"
      >
        <q-tooltip>
          {{ fromSearch ? 'Retour aux résultats de la recherche' : 'Retour aux postes' }}
        </q-tooltip>
      </q-btn>
      <div class="text-h5 row items-center no-wrap">
        <!-- Leading, same dot as the list: the fiche answers « allumé ? » at a glance too. -->
        <q-icon
          v-if="machine"
          :name="onlineIcon(machine.is_online)"
          :color="onlineColor(machine.is_online)"
          size="14px"
          class="q-mr-sm"
        >
          <q-tooltip>
            {{ onlineLabel(machine.is_online) }} — dernier contact
            {{ timeAgoLabel(machine.last_seen) }}
          </q-tooltip>
        </q-icon>
        {{ title }}
      </div>
      <!-- Only when the fiche was opened from a list query: elsewhere there is
           no search to walk, and dead arrows would be worse than none. -->
      <template v-if="fromSearch">
        <q-btn
          flat
          dense
          round
          icon="chevron_left"
          class="q-ml-md"
          :disable="!previousMachine"
          @click="goPrevious"
        >
          <q-tooltip>
            {{
              previousMachine
                ? `Précédent : ${previousMachine.hostname || previousMachine.machine_uuid}`
                : 'Premier résultat'
            }}
          </q-tooltip>
        </q-btn>
        <q-btn flat dense round icon="chevron_right" :disable="!nextMachine" @click="goNext">
          <q-tooltip>
            {{
              nextMachine
                ? `Suivant : ${nextMachine.hostname || nextMachine.machine_uuid}`
                : 'Dernier résultat'
            }}
          </q-tooltip>
        </q-btn>
        <div v-if="positionLabel" class="text-caption text-grey q-ml-sm">
          {{ positionLabel }}
        </div>
      </template>
      <q-space />
      <div v-if="lastRefreshedAt" class="text-caption text-grey q-mr-sm">
        Actualisé à {{ lastRefreshLabel }}
      </div>
      <q-btn flat dense round icon="refresh" :loading="loading" class="q-mr-sm" @click="load">
        <q-tooltip>{{ autoRefreshHint }}</q-tooltip>
      </q-btn>
      <q-btn-dropdown color="primary" dense label="Action" icon="bolt" :disable="!machine">
        <q-list>
          <template v-for="section in actionGroups" :key="section.group">
            <q-item-label header class="q-py-xs">{{ section.label }}</q-item-label>
            <q-item
              v-for="action in section.actions"
              :key="action.type"
              v-close-popup
              clickable
              @click="runOne(action)"
            >
              <q-item-section avatar><q-icon :name="action.icon" /></q-item-section>
              <q-item-section>{{ action.label }}</q-item-section>
            </q-item>
          </template>
        </q-list>
      </q-btn-dropdown>
      <!-- Admin only: the merge endpoint requires machine:write, so for a
           read-only operator the button could only ever open a dialog and 403.
           The count rides in the label — "Fusionner" said nothing about whether
           there was anything to fuse, which is what made it look inert. -->
      <q-btn
        v-if="auth.isAdmin"
        flat
        dense
        color="primary"
        icon="merge"
        :label="mergeLabel"
        class="q-ml-sm"
        :disable="!machine"
        @click="openMerge"
      >
        <q-tooltip>{{ mergeHint }}</q-tooltip>
      </q-btn>
      <!-- One slot, two states: revoking and lifting the revocation are the
           two halves of the same kill-switch, and showing both at once would
           read as a choice when only one ever applies. -->
      <q-btn
        v-if="auth.isAdmin && machine?.token_revoked"
        flat
        dense
        color="positive"
        icon="key"
        label="Autoriser le ré-enrôlement"
        class="q-ml-sm"
        @click="confirmAllowReenroll"
      />
      <q-btn
        v-else-if="auth.isAdmin"
        flat
        dense
        color="negative"
        icon="key_off"
        label="Révoquer le token"
        class="q-ml-sm"
        :disable="!machine"
        @click="confirmRevoke"
      />
    </div>

    <q-banner v-if="machine?.token_revoked" class="bg-red-2 q-mb-md" rounded>
      <template #avatar><q-icon name="key_off" color="negative" /></template>
      Token révoqué : le poste est coupé du serveur et ne peut plus se ré-enrôler, même avec le
      secret du parc, tant que le ré-enrôlement n'est pas autorisé ici.
      <template #action>
        <q-btn
          v-if="auth.isAdmin"
          flat
          dense
          label="Autoriser le ré-enrôlement"
          @click="confirmAllowReenroll"
        />
      </template>
    </q-banner>

    <q-banner v-if="machine?.needs_verification" class="bg-orange-2 q-mb-md" rounded>
      <template #avatar><q-icon name="warning" color="orange" /></template>
      Empreinte divergente : ce poste nécessite une vérification manuelle (clone, swap matériel ou
      ré-image).
      <template #action>
        <q-btn v-if="auth.isAdmin" flat dense label="Fusionner un doublon" @click="openMerge" />
      </template>
    </q-banner>

    <div v-if="machine" class="row q-col-gutter-md">
      <MachineIdentityCard :machine="machine" />
      <MachineDefenderCard :machine="machine" />
      <MachineWindowsUpdateCard :machine="machine" />
      <MachineAntivirusCard :machine="machine" />
    </div>

    <MachinePendingUpdatesCard v-if="machine" :machine="machine" :loading="loading" />

    <MachineThreatsCard
      v-model:pagination="threatPagination"
      :threats="threats"
      :loading="loading"
      @refresh="load"
    />

    <MachineCommandsCard
      v-model:pagination="commandPagination"
      :commands="commands"
      :loading="loading"
      @refresh="load"
      @show-detail="showDetail"
    />

    <MachineMergeDialog
      v-model="mergeOpen"
      :machine="machine"
      :machine-id="id"
      :duplicates="duplicates"
      @merged="load"
    />

    <CommandOutputDialog v-model="detailOpen" :command="detailCommand" :kind="detailKind" />
  </q-page>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { useQuasar } from 'quasar';
import { AUTO_REFRESH_INTERVAL_MS, useAutoRefresh } from 'src/composables/useAutoRefresh';
import { useMachineNavigation } from 'src/composables/useMachineNavigation';
import CommandOutputDialog from 'src/components/machine/CommandOutputDialog.vue';
import MachineAntivirusCard from 'src/components/machine/MachineAntivirusCard.vue';
import MachineCommandsCard from 'src/components/machine/MachineCommandsCard.vue';
import MachineDefenderCard from 'src/components/machine/MachineDefenderCard.vue';
import MachineIdentityCard from 'src/components/machine/MachineIdentityCard.vue';
import MachineMergeDialog from 'src/components/machine/MachineMergeDialog.vue';
import MachinePendingUpdatesCard from 'src/components/machine/MachinePendingUpdatesCard.vue';
import MachineThreatsCard from 'src/components/machine/MachineThreatsCard.vue';
import MachineWindowsUpdateCard from 'src/components/machine/MachineWindowsUpdateCard.vue';
import { DEFAULT_PAGE_SIZE, type TablePagination } from 'src/components/machine/types';
import {
  allowReenroll,
  getDuplicates,
  getMachine,
  revokeToken,
  wakeMachines,
  wakeNotification,
  type DuplicateCandidate,
  type MachineDetail,
} from 'src/services/machines';
import { useAuthStore } from 'src/stores/auth';
import { listThreats, type Threat } from 'src/services/threats';
import {
  commandActionGroups,
  createCommands,
  listCommands,
  type Command,
  type CommandAction,
} from 'src/services/commands';
import { apiErrorMessage } from 'src/services/errors';
import { onlineColor, onlineIcon, onlineLabel, timeAgoLabel } from 'src/utils/format';

const props = defineProps<{ id: string }>();
const $q = useQuasar();
const auth = useAuthStore();

const machine = ref<MachineDetail | null>(null);
const threats = ref<Threat[]>([]);
const commands = ref<Command[]>([]);
const loading = ref(false);
const mergeOpen = ref(false);
const duplicates = ref<DuplicateCandidate[]>([]);
const detailOpen = ref(false);
const detailCommand = ref<Command | null>(null);
const detailKind = ref<'output' | 'error'>('output');

// Previous/next through the search this fiche was opened from, and the back
// arrow's return query. Empty when the fiche was reached any other way.
const { fromSearch, previousMachine, nextMachine, positionLabel, backQuery, goPrevious, goNext } =
  useMachineNavigation();

// Both histories are paginated by the server: a poste that has been running for
// a year holds far more than a page of either, and the old behaviour silently
// showed the first fifty rows as if they were all of it. The cards own the page
// turning; the page owns the state and the refetch that follows it.
const threatPagination = ref<TablePagination>({
  page: 1,
  rowsPerPage: DEFAULT_PAGE_SIZE,
  rowsNumber: 0,
});
const commandPagination = ref<TablePagination>({
  page: 1,
  rowsPerPage: DEFAULT_PAGE_SIZE,
  rowsNumber: 0,
});

// The whole catalogue here, diagnostics included: reading one machine's
// gpresult or ipconfig is exactly what this page is for.
const actionGroups = commandActionGroups();

const title = computed(() => machine.value?.hostname || machine.value?.machine_uuid || 'Poste');

function showDetail(cmd: Command, kind: 'output' | 'error') {
  detailCommand.value = cmd;
  detailKind.value = kind;
  detailOpen.value = true;
}

// Which fetch is the current one. The 90 s background refresh, a page turn on
// either history, and a walk to the next poste can all be in flight together;
// without this the slowest answer would win and write its own stale page
// numbers back over whatever the reader has since asked for.
let requestId = 0;

async function fetchAll() {
  const id = ++requestId;
  const tp = threatPagination.value;
  const cp = commandPagination.value;
  const [m, t, c] = await Promise.all([
    getMachine(props.id),
    listThreats({ machine_id: props.id, page: tp.page, page_size: tp.rowsPerPage }),
    listCommands({ machine_id: props.id, page: cp.page, page_size: cp.rowsPerPage }),
  ]);
  if (id !== requestId) return;
  machine.value = m;
  threats.value = t.items;
  // Merged into the current value, not the snapshot: a page turned while this
  // request was in the air must not be undone by its answer.
  threatPagination.value = { ...threatPagination.value, rowsNumber: t.total };
  commands.value = c.items;
  commandPagination.value = { ...commandPagination.value, rowsNumber: c.total };
  // Not awaited with the rest: the count on the merge button is worth showing,
  // but never worth holding the page for.
  void fetchDuplicates();
}

/**
 * This is the page an administrator leaves open after firing a command, so it
 * follows the poste on its own: `pending` → `transmise` → `en cours` →
 * `réussie` arrives without a click.
 *
 * Paused while a dialog is over the page. The result dialog reads a snapshot
 * and would survive a refresh, but the merge dialog would have its duplicate
 * list swapped under the cursor — and either way, pulling the tables around
 * behind a modal is the one moment a background refresh is worse than stale
 * data.
 */
const { lastRefreshedAt, refreshNow } = useAutoRefresh(fetchAll, {
  paused: () => detailOpen.value || mergeOpen.value,
});

/** The manual load: this one shows the spinner, the automatic ones do not. */
async function load() {
  loading.value = true;
  try {
    await refreshNow();
  } finally {
    loading.value = false;
  }
}

const lastRefreshLabel = computed(() =>
  lastRefreshedAt.value ? lastRefreshedAt.value.toLocaleTimeString('fr-FR') : '',
);

const autoRefreshHint = `Actualiser — automatique toutes les ${Math.round(
  AUTO_REFRESH_INTERVAL_MS / 1000,
)} s`;

function runOne(action: CommandAction) {
  if (!action.confirm) {
    void send(action);
    return;
  }
  $q.dialog({
    title: action.label,
    message: [`Lancer « ${action.label} » sur ce poste ?`, action.hint].filter(Boolean).join(' '),
    cancel: true,
    persistent: true,
  }).onOk(() => {
    void send(action);
  });
}

async function send(action: CommandAction) {
  // The wake is not a command: the poste is off, so there is nothing to queue
  // for an agent that is not running. Same menu entry, same confirmation path,
  // a different call.
  if (action.serverSide) {
    await sendWake();
    return;
  }
  try {
    const res = await createCommands({ type: action.type, machine_ids: [props.id] });
    if (res.count === 0) {
      // The server de-duplicates per (poste, type). Saying "envoyée" here would
      // have the administrator watch a history that never grows a row.
      $q.notify({
        type: 'warning',
        message: `« ${action.label} » est déjà en attente sur ce poste.`,
      });
    } else {
      $q.notify({ type: 'positive', message: 'Commande envoyée' });
    }
    await load();
  } catch (e) {
    $q.notify({ type: 'negative', message: apiErrorMessage(e, "Échec de l'envoi de la commande") });
  }
}

async function sendWake() {
  try {
    const res = await wakeMachines([props.id]);
    $q.notify(wakeNotification(res));
    // Reloaded for the history, not for the machine's state: the wake is
    // recorded as a command row, while the poste itself will not reappear until
    // its agent reports — a minute or so after it has actually booted.
    await load();
  } catch (e) {
    $q.notify({ type: 'negative', message: apiErrorMessage(e, 'Échec du réveil') });
  }
}

function confirmRevoke() {
  $q.dialog({
    title: 'Révoquer le token',
    message:
      'Le poste sera coupé du serveur et ne pourra pas revenir — même avec le secret du parc — ' +
      'tant que le ré-enrôlement ne sera pas autorisé depuis cette page. Continuer ?',
    cancel: true,
    persistent: true,
  }).onOk(() => {
    void doRevoke();
  });
}

async function doRevoke() {
  try {
    await revokeToken(props.id);
    $q.notify({ type: 'positive', message: 'Token révoqué' });
    await load();
  } catch (e) {
    $q.notify({ type: 'negative', message: apiErrorMessage(e, 'Échec de la révocation') });
  }
}

function confirmAllowReenroll() {
  $q.dialog({
    title: 'Autoriser le ré-enrôlement',
    message:
      "L'ancien token reste invalide ; le poste reviendra de lui-même à sa prochaine tentative " +
      "d'enrôlement, dans les minutes qui suivent s'il est allumé. Continuer ?",
    cancel: true,
    persistent: true,
  }).onOk(() => {
    void doAllowReenroll();
  });
}

async function doAllowReenroll() {
  try {
    await allowReenroll(props.id);
    $q.notify({ type: 'positive', message: 'Ré-enrôlement autorisé' });
    await load();
  } catch (e) {
    $q.notify({ type: 'negative', message: apiErrorMessage(e, "Échec de l'autorisation") });
  }
}

// The count in the label, so the button says whether it has anything to offer
// before it is pressed — its silence on that is what made it look broken.
const mergeLabel = computed(() =>
  duplicates.value.length ? `Fusionner (${duplicates.value.length})` : 'Fusionner',
);

const mergeHint = computed(() =>
  duplicates.value.length
    ? `${duplicates.value.length} doublon(s) possible(s) détecté(s)`
    : 'Aucun doublon détecté — la recherche manuelle reste possible',
);

/** Candidates for the button's count, refreshed with the page. Admin-only: the
 * merge itself is, and a read-only console has no use for the list. */
async function fetchDuplicates() {
  if (!auth.isAdmin) return;
  try {
    const id = props.id;
    const found = await getDuplicates(id);
    // The reader may have walked to the next poste while this was in the air.
    if (id !== props.id) return;
    duplicates.value = found;
  } catch {
    // A failed candidate lookup must not take the fiche down with it: the
    // button simply falls back to its countless label.
    duplicates.value = [];
  }
}

function openMerge() {
  mergeOpen.value = true;
  void fetchDuplicates();
}

// Walking to the previous/next result changes the route param on the *same*
// component instance — nothing remounts, so the reload has to be watched for.
// Everything on screen belongs to the poste being left, `machine` included:
// held on to, the header, the banners and the merge dialog would spend a round
// trip describing one poste under another one's name. Both histories go back to
// their first page for the same reason.
watch(
  () => props.id,
  () => {
    machine.value = null;
    threats.value = [];
    commands.value = [];
    duplicates.value = [];
    threatPagination.value = { page: 1, rowsPerPage: DEFAULT_PAGE_SIZE, rowsNumber: 0 };
    commandPagination.value = { page: 1, rowsPerPage: DEFAULT_PAGE_SIZE, rowsNumber: 0 };
    void load();
  },
);

// The profile is fetched by the layout without being awaited, so on a hard
// reload of this page `isAdmin` is still false when the first load runs and the
// admin-only candidate lookup is skipped. The buttons appear on their own once
// it resolves; the count behind them would not, and a merge button reading
// "aucun doublon" on a poste that has one is the very thing this change set out
// to fix.
watch(
  () => auth.isAdmin,
  (isAdmin) => {
    if (isAdmin) void fetchDuplicates();
  },
);

onMounted(load);
</script>
