import { defineBoot } from '#q-app/wrappers';
import axios, { type AxiosInstance } from 'axios';

declare module 'vue' {
  interface ComponentCustomProperties {
    $api: AxiosInstance;
  }
}

const api = axios.create({
  baseURL: process.env.API_BASE_URL || '/api/v1',
});

export default defineBoot(({ app }) => {
  app.config.globalProperties.$api = api;
});

export { api };
