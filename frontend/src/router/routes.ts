import type { RouteRecordRaw } from 'vue-router';

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    meta: { title: 'Connexion' },
    component: () => import('pages/LoginPage.vue'),
  },
  // Parcours « mot de passe oublié » : pages publiques, atteintes sans session
  // (depuis la page de connexion, ou depuis le lien reçu par e-mail).
  {
    path: '/forgot-password',
    name: 'forgot-password',
    meta: { title: 'Mot de passe oublié' },
    component: () => import('pages/ForgotPasswordPage.vue'),
  },
  {
    path: '/reset-password',
    name: 'reset-password',
    meta: { title: 'Nouveau mot de passe' },
    component: () => import('pages/ResetPasswordPage.vue'),
  },
  {
    path: '/',
    component: () => import('layouts/MainLayout.vue'),
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        name: 'dashboard',
        meta: { title: 'Tableau de bord' },
        component: () => import('pages/DashboardPage.vue'),
      },
      {
        path: 'machines',
        name: 'machines',
        meta: { title: 'Postes' },
        component: () => import('pages/MachinesPage.vue'),
      },
      {
        path: 'software',
        name: 'software',
        meta: { title: 'Logiciels' },
        component: () => import('pages/SoftwarePage.vue'),
      },
      {
        path: 'machines/:id',
        name: 'machine-detail',
        // Replaced by the poste's name once loaded (MachineDetailPage).
        meta: { title: 'Poste' },
        component: () => import('pages/MachineDetailPage.vue'),
        props: true,
      },
      {
        path: 'users',
        name: 'users',
        component: () => import('pages/UsersPage.vue'),
        meta: { requiresAdmin: true, title: 'Utilisateurs' },
      },
      {
        path: 'account',
        name: 'account',
        meta: { title: 'Mon compte' },
        component: () => import('pages/AccountPage.vue'),
      },
    ],
  },
  {
    path: '/:catchAll(.*)*',
    meta: { title: 'Page introuvable' },
    component: () => import('pages/ErrorNotFound.vue'),
  },
];

export default routes;
