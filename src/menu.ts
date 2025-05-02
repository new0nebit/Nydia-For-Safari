import { icons } from './icons';
import {
  getSettings,
  setNotificationDisplayer,
  setOnSettingsComplete,
  showSettingsForm,
  validateSettings,
} from './settings';
import { getAllStoredCredentialsFromDB } from './store';
import { StoredCredential } from './types';

type NotificationType = 'success' | 'error' | 'info' | 'warning';
type ModalType = 'alert' | 'confirm' | 'prompt';

interface SyncUploadResult {
  uploadedCount: number;
  failedCount: number;
  error: boolean;
}
interface SyncDownloadResult {
  syncedCount: number;
  failedCount: number;
  empty: boolean;
  error: boolean;
}

// IndexedDB
const DB_NAME = 'NydiaDB';
const DB_VERSION = 3;
const STORE_NAME = 'storedCredentials';

// DOM helper: create element with optional class list and innerHTML.
function create<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  classes: string[] = [],
  html?: string,
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (classes.length) el.classList.add(...classes);
  if (html !== undefined) el.innerHTML = html;
  return el;
}

// DOM helper: create a button containing icon + label and attach click handler.
function createButton(
  icon: string,
  label: string,
  classes: string[],
  handler: (btn: HTMLButtonElement) => void,
): HTMLButtonElement {
  const btn = create('button', classes) as HTMLButtonElement;
  btn.innerHTML = `${icon}<span>${label}</span>`;
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    handler(btn);
  });
  return btn;
}

// Update button text (span) safely.
function setButtonLabel(btn: HTMLButtonElement, label: string): void {
  const span = btn.querySelector('span');
  if (span) span.textContent = label;
}

// Notification dispatcher.
function notify(type: NotificationType, title: string, message: string): void {
  const iconMap: Record<NotificationType, string> = {
    success: icons.check,
    error: icons.alert,
    warning: icons.warning,
    info: icons.info,
  };
  const alert = create('div', ['alert', `alert-${type}`], `
    ${iconMap[type]}
    <div class="alert-content">
      <h5 class="alert-title">${title}</h5>
      <div class="alert-description">${message}</div>
    </div>
  `);
  const root = document.getElementById('root');
  root?.prepend(alert);
  setTimeout(() => alert.remove(), 3_000);
}

// Modal dialog builder; resolves with boolean result.
function modal(type: ModalType, title: string, message: string): Promise<boolean> {
  return new Promise((resolve) => {
    const iconMap: Record<ModalType, string> = {
      alert: icons.info,
      confirm: icons.question,
      prompt: icons.warning,
    };
    const overlay = create('div', ['modal-overlay'], `
      <div class="modal-content">
        <div class="modal-header">
          ${iconMap[type]}
          <div>
            <div class="modal-title">${title}</div>
            <div class="modal-message">${message}</div>
          </div>
        </div>
        <div class="modal-buttons">
          ${
            type === 'confirm'
              ? '<button class="modal-cancel">Cancel</button><button class="modal-confirm">Confirm</button>'
              : '<button class="modal-confirm">OK</button>'
          }
        </div>
      </div>
    `);
    const close = (ok: boolean) => {
      overlay.remove();
      resolve(ok);
    };
    overlay.querySelector('.modal-confirm')?.addEventListener('click', () => close(true));
    overlay.querySelector('.modal-cancel')?.addEventListener('click', () => close(false));
    document.body.appendChild(overlay);
  });
}

// Ensures missing indices exist without bumping DB_VERSION.
function ensureIndex(store: IDBObjectStore, name: string, keyPath: string, opts?: IDBIndexParameters) {
  if (!store.indexNames.contains(name)) store.createIndex(name, keyPath, opts);
}

// Extract eTLD+1 from rpId.
function rootDomain(rpId: string): string {
  const parts = rpId.toLowerCase().split('.');
  return parts.length > 2 ? parts.slice(-2).join('.') : rpId;
}

// Reset "Sync Passkeys" button to default look.
function resetSyncButton(btn: HTMLButtonElement): void {
  btn.disabled = false;
  btn.classList.remove('uploading');
  btn.innerHTML = `${icons.sia}<span>Sync Passkeys</span>`;
}

/* -------------------------------------------------------------------------- */
/*                                   MENU                                     */
/* -------------------------------------------------------------------------- */
export class Menu {
  constructor() {
    setNotificationDisplayer({ showNotification: notify });
    setOnSettingsComplete(() => this.render());

    document.addEventListener('DOMContentLoaded', () => this.render());
  }

  /* --------------------------- MAIN RENDER LOOP -------------------------- */
  private async render(): Promise<void> {
    try {
      const passkeyList = document.getElementById('passkey-list');
      if (!passkeyList) return;

      const [creds, settings] = await Promise.all([
        getAllStoredCredentialsFromDB(),
        getSettings(),
      ]);
      creds.sort((a, b) => (b.creationTime ?? 0) - (a.creationTime ?? 0));

      // Header (insert once)
      if (!document.querySelector('.header-container')) {
        this.buildHeader(passkeyList);
      }

      passkeyList.innerHTML = '';

      if (creds.length) {
        creds.forEach((c) => passkeyList.appendChild(this.passkeyItem(c)));
      } else if (settings) {
        this.stateView(passkeyList, {
          title: 'Ready to Sync Passkeys',
          subtitle: 'Connect to renterd server and retrieve passkeys',
          icon: icons.sia,
          label: 'Sync Passkeys',
          btnClass: 'button-sync',
          action: (btn) => this.sync(btn),
        });
      } else {
        this.stateView(passkeyList, {
          title: 'No Passkeys Found',
          subtitle: 'Configure renterd settings to start syncing',
          icon: icons.settings,
          label: 'Renterd Settings',
          btnClass: 'button-green',
          action: () => showSettingsForm(),
        });
      }
    } catch (err) {
      console.error('render error:', err);
      notify('error', 'Error', 'Failed to load passkeys.');
    }
  }

  /* ------------------------------ HEADER ------------------------------ */
  private buildHeader(listRoot: HTMLElement): void {
    const header = create('div', ['header-container']);
    header.append(
      create('div', ['logo-container'], icons.logo),
      this.burgerMenu(),
    );
    listRoot.parentElement?.prepend(header);
  }

  private burgerMenu(): HTMLElement {
    const wrap = create('div', ['menu-container']);
    const burger = create('button', ['burger-button'], icons.burger) as HTMLButtonElement;
    const menu = create('div', ['burger-menu', 'hidden']);

    const toggle = () => {
      burger.classList.toggle('active');
      menu.classList.toggle('hidden');
    };

    burger.addEventListener('click', (e) => {
      e.stopPropagation();
      toggle();
    });
    document.addEventListener('click', (e) => {
      if (!wrap.contains(e.target as Node) && !menu.classList.contains('hidden')) toggle();
    });

    menu.append(
      createButton(icons.sia, 'Sync Passkeys', ['menu-item'], async (btn) => {
        btn.disabled = true;
        await this.sync(btn);
        btn.disabled = false;
        toggle();
      }),
      createButton(icons.settings, 'Renterd Settings', ['menu-item'], () => {
        showSettingsForm();
        toggle();
      }),
    );

    wrap.append(burger, menu);
    return wrap;
  }

  /* ------------------------------ EMPTY STATE ------------------------------ */
  private stateView(
    parent: HTMLElement,
    opts: {
      title: string;
      subtitle: string;
      icon: string;
      label: string;
      btnClass: string;
      action: (btn: HTMLButtonElement) => void;
    },
  ): void {
    const box = create('div', ['centered-container']);
    box.append(
      create('div', ['small-title'], opts.title),
      create('div', ['small-subtitle'], opts.subtitle),
      (() => {
        const wrap = create('div', ['flex-center']);
        const btn = createButton(opts.icon, opts.label, ['button', opts.btnClass, 'button-gap'], opts.action);
        wrap.appendChild(btn);
        return wrap;
      })(),
    );
    parent.appendChild(box);
  }

  /* ------------------------------ LIST ITEM ------------------------------ */
  private passkeyItem(passkey: StoredCredential): HTMLLIElement {
    const li = create('li', ['passkey-item']) as HTMLLIElement;

    // site info
    const site = create('div', ['site-info']);
    const icon = create('img', ['site-icon']) as HTMLImageElement;
    icon.src = `https://www.google.com/s2/favicons?domain=${rootDomain(passkey.rpId)}&sz=64`;
    icon.alt = passkey.rpId;
    site.append(icon, create('span', [], passkey.rpId.replace(/^www\./, '')));

    // user info
    const user = create('div', ['user-info'], `${icons.user}<span>${passkey.userName || 'Unknown User'}</span>`);

    // actions
    const actions = create('div', ['action-container']);
    const backup = createButton(
      passkey.isSynced ? icons.check : icons.sia,
      passkey.isSynced ? 'Synced' : 'Backup to Sia',
      ['button', passkey.isSynced ? 'button-sync' : 'button-green'],
      (btn) => this.backup(passkey, btn),
    );
    const del = createButton(icons.delete, 'Delete', ['button', 'button-red'], () => this.remove(passkey.uniqueId));
    actions.append(backup, del);

    li.append(site, user, actions);
    return li;
  }

  /* ------------------------------ DELETE ------------------------------ */
  private async remove(uniqueId: string): Promise<void> {
    if (!(await modal('confirm', 'Delete Passkey', 'Are you sure you want to delete this Passkey?'))) return;

    try {
      const db = await this.openDb();
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).delete(uniqueId).onsuccess = () => {
        notify('success', 'Deleted', 'Passkey deleted successfully.');
        this.render();
      };
      tx.onerror = () => notify('error', 'Error', 'Failed to delete passkey.');
    } catch (err) {
      console.error('remove error:', err);
      notify('error', 'Error', 'Failed to delete passkey.');
    }
  }

  /* ------------------------------ BACKUP ONE ------------------------------ */
  private async backup(passkey: StoredCredential, btn: HTMLButtonElement): Promise<void> {
    btn.disabled = true;
    btn.classList.add('uploading');
    setButtonLabel(btn, 'Backing up...');

    try {
      const res = await browser.runtime.sendMessage({ type: 'uploadToSia', passkeyData: passkey });
      if (res?.success) {
        Object.assign(passkey, { isSynced: true });
        btn.classList.replace('button-green', 'button-sync');
        btn.innerHTML = `${icons.check}<span>Synced</span>`;
        notify('success', 'Success', res.message);
      } else {
        throw new Error(res?.error ?? 'Upload failed');
      }
    } catch (err) {
      console.error('backup error:', err);
      notify('error', 'Error', String(err));
      btn.innerHTML = `${passkey.isSynced ? icons.check : icons.sia}<span>${passkey.isSynced ? 'Synced' : 'Backup to Sia'}</span>`;
    } finally {
      btn.disabled = false;
      btn.classList.remove('uploading');
    }
  }

  /* ------------------------------ SYNC ------------------------------ */
  private async sync(btn: HTMLButtonElement): Promise<void> {
    btn.disabled = true;
    setButtonLabel(btn, 'Syncing…');

    const settings = await getSettings();
    if (!settings || !validateSettings(settings)) {
      notify('error', 'Error', 'No renterd settings found.');
      resetSyncButton(btn);
      return;
    }

    try {
      const [uploadRes, downloadRes] = await Promise.all([this.uploadUnsynced(), this.downloadNew()]);

      let type: NotificationType;
      let msg: string;

      if (uploadRes.error || downloadRes.error) {
        type = 'error';
        msg = 'Error syncing Passkeys with renterd server.';
      } else if (uploadRes.failedCount || downloadRes.failedCount) {
        type = 'warning';
        msg = 'Some passkeys failed to synchronize.';
      } else if (downloadRes.empty) {
        type = 'info';
        msg = 'No new passkeys found on renterd server.';
      } else {
        type = 'success';
        msg = `Synchronized ${downloadRes.syncedCount} passkey(s).`;
      }

      notify(type, type.charAt(0).toUpperCase() + type.slice(1), msg);
      await this.render();
    } catch (err) {
      console.error('sync error:', err);
      notify('error', 'Error', 'Error syncing Passkeys with renterd server.');
    } finally {
      resetSyncButton(btn);
    }
  }

  private async uploadUnsynced(): Promise<SyncUploadResult> {
    const all = await getAllStoredCredentialsFromDB();
    const unsynced = all.filter((c) => !c.isSynced);
    if (!unsynced.length) return { uploadedCount: 0, failedCount: 0, error: false };

    try {
      const res = await browser.runtime.sendMessage({ type: 'uploadUnsyncedPasskeys', passkeys: unsynced });
      return {
        uploadedCount: res?.uploadedCount ?? 0,
        failedCount: res?.failedCount ?? 0,
        error: !res?.success,
      };
    } catch (err) {
      console.error('uploadUnsynced error:', err);
      return { uploadedCount: 0, failedCount: unsynced.length, error: true };
    }
  }

  private async downloadNew(): Promise<SyncDownloadResult> {
    try {
      const res = await browser.runtime.sendMessage({ type: 'syncFromSia' });
      return {
        syncedCount: res?.syncedCount ?? 0,
        failedCount: res?.failedCount ?? 0,
        empty: !res?.syncedCount && !res?.failedCount,
        error: !res?.success,
      };
    } catch (err) {
      console.error('downloadNew error:', err);
      return { syncedCount: 0, failedCount: 0, empty: true, error: true };
    }
  }

  /* ------------------------------ IndexedDB ------------------------------ */
  private openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);

      req.onupgradeneeded = () => {
        const db = req.result;
        let store: IDBObjectStore;

        if (!db.objectStoreNames.contains(STORE_NAME)) {
          store = db.createObjectStore(STORE_NAME, { keyPath: 'uniqueId' });
        } else {
          const tx = req.transaction!;
          store = tx.objectStore(STORE_NAME);
        }

        ensureIndex(store, 'credentialId', 'credentialId', { unique: true });
        ensureIndex(store, 'rpId', 'rpId');
        if (!db.objectStoreNames.contains('settings')) {
          db.createObjectStore('settings', { keyPath: 'id' });
        }
      };

      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
}

/* -------------------------------------------------------------------------- */
/*                                    BOOT                                    */
/* -------------------------------------------------------------------------- */
new Menu();
