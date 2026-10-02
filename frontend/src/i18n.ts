import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

// Phase 1 translation surface. Hitting every string in the app is a multi-
// release project; this release covers the top-level nav, the Dashboard tab
// labels, the common action button labels, the Admin tab headers, the
// cheat-sheet section titles and a handful of empty-state copy. Everything
// else continues to render in English until a follow-up translates it.

export const SUPPORTED_LOCALES = ['en', 'tr'] as const;
export type SupportedLocale = typeof SUPPORTED_LOCALES[number];

const STORAGE_KEY = 'uiLocale';

export function loadInitialLocale(): SupportedLocale {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored && (SUPPORTED_LOCALES as readonly string[]).includes(stored)) {
      return stored as SupportedLocale;
    }
  } catch {
    /* ignore */
  }
  // Fall back to the browser language's two-letter code when it matches.
  const nav = (typeof navigator !== 'undefined' ? navigator.language : '').slice(0, 2);
  if ((SUPPORTED_LOCALES as readonly string[]).includes(nav)) {
    return nav as SupportedLocale;
  }
  return 'en';
}

export function persistLocale(locale: SupportedLocale) {
  try {
    localStorage.setItem(STORAGE_KEY, locale);
  } catch {
    /* ignore */
  }
}

const resources = {
  en: {
    translation: {
      nav: {
        dashboard: 'Dashboard',
        admin: 'Admin',
        logout: 'Log out',
        shortcuts: 'Shortcuts',
        theme: {
          light: 'Light',
          dark: 'Dark',
          system: 'System',
        },
        locale: 'Language',
      },
      dashboard: {
        overview: 'Overview',
        title: 'Cluster Resources',
        subtitle: 'Pick a namespace to inspect its authorized resources. Unauthorized resources are hidden.',
        search: 'Search {{resource}} · try label:app=foo…',
        searchGeneric: 'Search…',
        refresh: 'Refresh',
        namespacesPanel: 'Namespaces',
        namespacesSearch: 'Search namespaces…',
        namespacesEmpty: 'No namespaces available.',
        namespacesNoMatch: 'No namespaces match your search.',
        empty: 'No records available.',
        emptyFiltered: 'No matching records found.',
        noResourcePerms: 'You have no resource permissions in this namespace.',
        emptyHint: 'The namespace is empty or no records match your access.',
        views: {
          button: 'Views',
          title: 'Saved views',
          empty: 'No saved views yet.',
          save: 'Save current view',
          namePlaceholder: 'View name…',
        },
      },
      resources: {
        pods: 'Pods',
        deployments: 'Deployments',
        daemonsets: 'DaemonSets',
        statefulsets: 'StatefulSets',
        hpas: 'HPAs',
        services: 'Services',
        configmaps: 'ConfigMaps',
        ingresses: 'Ingresses',
        cronjobs: 'CronJobs',
        jobs: 'Jobs',
      },
      actions: {
        logs: 'Logs',
        events: 'Events',
        yaml: 'YAML',
        edit: 'Edit',
        scale: 'Scale',
        restart: 'Restart',
        shell: 'Shell',
        data: 'Data',
        apply: 'Apply',
        cancel: 'Cancel',
        close: 'Close',
        save: 'Save',
        reset: 'Reset',
        reload: 'Reload',
        dryRun: 'Dry-run',
      },
      admin: {
        tabs: {
          users: 'Users',
          groups: 'Groups',
          roles: 'Roles',
          ldap: 'LDAP',
          azure: 'Azure AD',
          session: 'Session',
          clusters: 'Clusters',
          customization: 'Customization',
          audit: 'Audit Logs',
          sessions: 'Sessions',
        },
      },
    },
  },
  tr: {
    translation: {
      nav: {
        dashboard: 'Panel',
        admin: 'Yönetim',
        logout: 'Çıkış',
        shortcuts: 'Kısayollar',
        theme: {
          light: 'Açık',
          dark: 'Koyu',
          system: 'Sistem',
        },
        locale: 'Dil',
      },
      dashboard: {
        overview: 'Genel bakış',
        title: 'Küme Kaynakları',
        subtitle: 'Yetkili olduğun kaynakları görmek için bir namespace seç. Yetkisiz olanlar gizlenir.',
        search: '{{resource}} ara · label:app=foo deneyin…',
        searchGeneric: 'Ara…',
        refresh: 'Yenile',
        namespacesPanel: 'Namespace\'ler',
        namespacesSearch: 'Namespace ara…',
        namespacesEmpty: 'Görünür namespace yok.',
        namespacesNoMatch: 'Aramanla eşleşen namespace yok.',
        empty: 'Kayıt yok.',
        emptyFiltered: 'Eşleşen kayıt bulunamadı.',
        noResourcePerms: 'Bu namespace\'te hiç kaynak yetkin yok.',
        emptyHint: 'Namespace boş ya da erişimine uyan kayıt yok.',
        views: {
          button: 'Görünümler',
          title: 'Kayıtlı görünümler',
          empty: 'Kayıtlı görünüm yok.',
          save: 'Mevcut görünümü kaydet',
          namePlaceholder: 'Görünüm adı…',
        },
      },
      resources: {
        pods: 'Pod\'lar',
        deployments: 'Deployment\'lar',
        daemonsets: 'DaemonSet\'ler',
        statefulsets: 'StatefulSet\'ler',
        hpas: 'HPA\'lar',
        services: 'Servisler',
        configmaps: 'ConfigMap\'ler',
        ingresses: 'Ingress\'ler',
        cronjobs: 'CronJob\'lar',
        jobs: 'Job\'lar',
      },
      actions: {
        logs: 'Loglar',
        events: 'Olaylar',
        yaml: 'YAML',
        edit: 'Düzenle',
        scale: 'Ölçekle',
        restart: 'Yeniden başlat',
        shell: 'Shell',
        data: 'Veri',
        apply: 'Uygula',
        cancel: 'İptal',
        close: 'Kapat',
        save: 'Kaydet',
        reset: 'Sıfırla',
        reload: 'Yeniden yükle',
        dryRun: 'Dry-run',
      },
      admin: {
        tabs: {
          users: 'Kullanıcılar',
          groups: 'Gruplar',
          roles: 'Roller',
          ldap: 'LDAP',
          azure: 'Azure AD',
          session: 'Oturum',
          clusters: 'Cluster\'lar',
          customization: 'Özelleştirme',
          audit: 'Denetim Logları',
          sessions: 'Oturumlar',
        },
      },
    },
  },
};

void i18n.use(initReactI18next).init({
  resources,
  lng: loadInitialLocale(),
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
});

export default i18n;
