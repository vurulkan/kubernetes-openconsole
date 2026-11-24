import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Input, MultiSelect, MultiSelectOption, TextArea } from '../../components/ui';
import { LdapImport } from '../../components/DirectoryImportPanel';
import {
  getAzureAD,
  getLDAP,
  testAzureAdConnection,
  testAzureGraph,
  testLdapConnection,
  updateAzureAD,
  updateLDAP,
} from '../../services/api';
import { SectionCard } from './SectionCard';
import { useDirectory, type DirectoryKind } from './useDirectory';

type TestStatus = { status: 'success' | 'error'; message: string } | null;

const emptyLdap = {
  enabled: false,
  url: '',
  host: '',
  port: 389,
  useSsl: false,
  startTls: false,
  sslSkipVerify: false,
  caCert: '',
  timeoutSeconds: 10,
  bindDn: '',
  bindPassword: '',
  userBaseDn: '',
  userBaseDns: [] as string[],
  userFilter: '',
  usernameAttribute: 'sAMAccountName',
  passwordConfigured: false,
  autoProvision: false,
  autoProvisionGroupIds: [] as number[],
};

const GROUPS: DirectoryKind[] = ['groups'];

/**
 * Admin → LDAP: the directory settings (the stored bind password is never
 * sent back unless replaced), the connection test and the user import.
 * Loads the LDAP settings and the groups (auto-provision, import).
 */
export const LdapSection: React.FC<{
  onUsersAdded: (names: string[]) => void;
  onError: (msg: string | null) => void;
}> = ({ onUsersAdded, onError }) => {
  const { t: tr } = useTranslation();
  const { groups } = useDirectory(GROUPS, onError);
  const [config, setConfig] = useState(emptyLdap);
  const [updatePassword, setUpdatePassword] = useState(false);
  const [testStatus, setTestStatus] = useState<TestStatus>(null);

  const load = useCallback(async () => {
    try {
      const c = await getLDAP();
      setConfig({
        enabled: c.enabled ?? false,
        url: c.url ?? '',
        host: c.host ?? '',
        port: c.port ?? 389,
        useSsl: c.useSsl ?? false,
        startTls: c.startTls ?? false,
        sslSkipVerify: c.sslSkipVerify ?? false,
        caCert: c.caCert ?? '',
        timeoutSeconds: c.timeoutSeconds ?? 10,
        bindDn: c.bindDn ?? '',
        bindPassword: '',
        userBaseDn: c.userBaseDn ?? '',
        userBaseDns: c.userBaseDns ?? [],
        userFilter: c.userFilter ?? '',
        usernameAttribute: c.usernameAttribute ?? 'sAMAccountName',
        passwordConfigured: c.passwordConfigured ?? false,
        autoProvision: c.autoProvision ?? false,
        autoProvisionGroupIds: c.autoProvisionGroupIds ?? [],
      });
      setUpdatePassword(false);
    } catch {
      /* the form keeps what it shows */
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async () => {
    setTestStatus(null);
    try {
      await updateLDAP({
        ...config,
        userBaseDns: config.userBaseDns.map((dn) => dn.trim()).filter(Boolean),
        bindPassword: updatePassword || !(config.passwordConfigured ?? false) ? config.bindPassword : '',
        passwordConfigured: config.passwordConfigured ?? false,
      });
    } catch (err) {
      // Shown where the test result goes, next to Save; the form keeps what was typed.
      setTestStatus({ status: 'error', message: (err as Error).message });
      return;
    }
    await load();
  };

  const test = async () => {
    setTestStatus(null);
    try {
      await testLdapConnection();
      setTestStatus({ status: 'success', message: tr('common.ldapTestOk') });
    } catch (err) {
      setTestStatus({ status: 'error', message: (err as Error).message || tr('admin.ldap.testFailed') });
    }
  };

  const passwordKept = !updatePassword && (config.passwordConfigured ?? false);

  return (
    <div className="flex flex-col gap-5">
      <SectionCard title={tr('admin.sections.ldap')}>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Checkbox checked={config.enabled} onChange={(v) => setConfig({ ...config, enabled: v })} label={tr('admin.ldap.enabled')} />
          <Input label={tr('admin.ldap.host')} value={config.host} onChange={(e) => setConfig({ ...config, host: e.target.value })} />
          <Input
            label={tr('admin.ldap.port')}
            type="number"
            value={config.port}
            onChange={(e) => setConfig({ ...config, port: Number(e.target.value) })}
          />
          <Checkbox checked={config.useSsl} onChange={(v) => setConfig({ ...config, useSsl: v })} label={tr('admin.ldap.useSsl')} />
          <Checkbox checked={config.startTls} onChange={(v) => setConfig({ ...config, startTls: v })} label={tr('admin.ldap.startTls')} />
          <Checkbox
            checked={config.sslSkipVerify}
            onChange={(v) => setConfig({ ...config, sslSkipVerify: v })}
            label={tr('admin.ldap.skipVerify')}
          />
          <div className="sm:col-span-2 lg:col-span-3">
            <TextArea
              label={tr('admin.ldap.caCert')}
              value={config.caCert}
              placeholder="-----BEGIN CERTIFICATE-----"
              onChange={(v) => setConfig({ ...config, caCert: v })}
            />
          </div>
          <Input
            label={tr('admin.ldap.timeout')}
            type="number"
            value={config.timeoutSeconds}
            onChange={(e) => setConfig({ ...config, timeoutSeconds: Number(e.target.value) })}
          />
          <Input label={tr('admin.ldap.bindDn')} value={config.bindDn} onChange={(e) => setConfig({ ...config, bindDn: e.target.value })} />
          <Checkbox checked={updatePassword} onChange={setUpdatePassword} label={tr('common.updateBindPassword')} />
          <Input
            label={tr('common.bindPassword')}
            type="password"
            disabled={passwordKept}
            value={passwordKept ? tr('common.configured') : config.bindPassword}
            onChange={(e) => setConfig({ ...config, bindPassword: e.target.value })}
          />
          <Input
            label={tr('common.userBaseDnSingle')}
            value={config.userBaseDn}
            onChange={(e) => setConfig({ ...config, userBaseDn: e.target.value })}
          />
          {/* One DN per line: a DN has commas of its own. */}
          <TextArea
            label={tr('common.userBaseDnMulti')}
            value={config.userBaseDns.join('\n')}
            placeholder={'OU=Users,DC=example,DC=com\nOU=Admins,DC=example,DC=com'}
            onChange={(v) => setConfig({ ...config, userBaseDns: v.split('\n') })}
          />
          <Input
            label={tr('common.userFilter')}
            value={config.userFilter}
            onChange={(e) => setConfig({ ...config, userFilter: e.target.value })}
          />
          <Input
            label={tr('common.usernameAttribute')}
            value={config.usernameAttribute}
            onChange={(e) => setConfig({ ...config, usernameAttribute: e.target.value })}
          />
        </div>
        <div className="mt-5 rounded-xl border border-slate-200 p-4 dark:border-slate-800">
          <Checkbox
            checked={config.autoProvision}
            onChange={(v) => setConfig({ ...config, autoProvision: v })}
            label={tr('admin.ldap.autoProvision')}
          />
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{tr('admin.ldap.autoProvisionHelp')}</p>
          {config.autoProvision && (
            <>
              <MultiSelect
                label={tr('admin.ldap.autoProvisionGroups')}
                className="mt-3"
                options={groups.map((g) => ({ id: g.id, label: g.name }))}
                value={groups
                  .filter((g) => config.autoProvisionGroupIds.includes(g.id))
                  .map((g) => ({ id: g.id, label: g.name }))}
                onChange={(value: MultiSelectOption[]) =>
                  setConfig({ ...config, autoProvisionGroupIds: value.map((v) => Number(v.id)) })
                }
                noOptionsText={tr('ldapImport.noGroups')}
                placeholder={tr('ldapImport.groupsPlaceholder')}
              />
              <Alert severity="warning" className="mt-3">
                {tr('admin.ldap.autoProvisionWarning')}
              </Alert>
            </>
          )}
        </div>
        <div className="mt-4 flex gap-2">
          <Button variant="primary" size="sm" onClick={save}>
            {tr('admin.ldap.save')}
          </Button>
          <Button variant="outline" size="sm" onClick={test}>
            {tr('admin.ldap.test')}
          </Button>
        </div>
        {testStatus && (
          <Alert severity={testStatus.status} className="mt-3">
            {testStatus.message}
          </Alert>
        )}
      </SectionCard>

      <SectionCard title={tr('admin.cards.importLdapUsers')}>
        <LdapImport
          groups={groups}
          onImported={(names) => {
            if (names.length > 0) onUsersAdded(names);
          }}
        />
      </SectionCard>
    </div>
  );
};

/**
 * Admin → Azure AD: the app registration (the stored client secret is never
 * sent back unless replaced) and the configuration test. Loads only its settings.
 */
export const AzureAdSection: React.FC = () => {
  const { t: tr } = useTranslation();
  const [config, setConfig] = useState({
    enabled: false,
    tenantId: '',
    clientId: '',
    clientSecret: '',
    redirectUrl: '',
    passwordConfigured: false,
    requireMfa: false,
    graphSearch: false,
  });
  const [updateSecret, setUpdateSecret] = useState(false);
  const [testStatus, setTestStatus] = useState<TestStatus>(null);
  const [graphStatus, setGraphStatus] = useState<TestStatus>(null);

  const load = useCallback(async () => {
    try {
      const c = await getAzureAD();
      setConfig({
        enabled: c.enabled ?? false,
        tenantId: c.tenantId ?? '',
        clientId: c.clientId ?? '',
        clientSecret: '',
        redirectUrl: c.redirectUrl ?? '',
        passwordConfigured: c.passwordConfigured ?? false,
        requireMfa: c.requireMfa ?? false,
        graphSearch: c.graphSearch ?? false,
      });
      setUpdateSecret(false);
    } catch {
      /* the form keeps what it shows */
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async () => {
    setTestStatus(null);
    try {
      await updateAzureAD({
        ...config,
        clientSecret: updateSecret || !(config.passwordConfigured ?? false) ? config.clientSecret : '',
        passwordConfigured: config.passwordConfigured ?? false,
      });
    } catch (err) {
      setTestStatus({ status: 'error', message: (err as Error).message });
      return;
    }
    await load();
  };

  const test = async () => {
    setTestStatus(null);
    try {
      await testAzureAdConnection();
      setTestStatus({ status: 'success', message: tr('common.azureTestOk') });
    } catch (err) {
      setTestStatus({ status: 'error', message: (err as Error).message || tr('admin.azure.testFailed') });
    }
  };

  const secretKept = !updateSecret && (config.passwordConfigured ?? false);

  // The switch saves at once, with the stored settings (not edits still open in the card above).
  const setGraphSearch = async (on: boolean) => {
    setGraphStatus(null);
    try {
      const saved = await getAzureAD();
      await updateAzureAD({ ...saved, clientSecret: '', passwordConfigured: saved.passwordConfigured ?? false, graphSearch: on });
      setConfig((c) => ({ ...c, graphSearch: on }));
    } catch (err) {
      setGraphStatus({ status: 'error', message: (err as Error).message });
    }
  };

  const testGraph = async () => {
    setGraphStatus(null);
    try {
      await testAzureGraph();
      setGraphStatus({ status: 'success', message: tr('admin.azureGraph.testOk') });
    } catch (err) {
      setGraphStatus({ status: 'error', message: tr('admin.azureGraph.failed', { reason: (err as Error).message }) });
    }
  };

  return (
    <div className="flex flex-col gap-5">
      <SectionCard title={tr('admin.sections.azureAd')}>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Checkbox checked={config.enabled} onChange={(v) => setConfig({ ...config, enabled: v })} label={tr('admin.ldap.enabled')} />
          <Input
            label={tr('admin.azure.tenantId')}
            value={config.tenantId}
            onChange={(e) => setConfig({ ...config, tenantId: e.target.value })}
          />
          <Input
            label={tr('admin.azure.clientId')}
            value={config.clientId}
            onChange={(e) => setConfig({ ...config, clientId: e.target.value })}
          />
          <Input
            label={tr('admin.azure.redirectUrl')}
            value={config.redirectUrl}
            onChange={(e) => setConfig({ ...config, redirectUrl: e.target.value })}
            placeholder={`${window.location.origin}/api/auth/azure/callback`}
          />
          <Checkbox checked={updateSecret} onChange={setUpdateSecret} label={tr('common.updateClientSecret')} />
          <Input
            label={tr('common.clientSecret')}
            type="password"
            disabled={secretKept}
            value={secretKept ? tr('common.configured') : config.clientSecret}
            onChange={(e) => setConfig({ ...config, clientSecret: e.target.value })}
          />
          <div className="sm:col-span-2">
            <Checkbox checked={config.requireMfa} onChange={(v) => setConfig({ ...config, requireMfa: v })} label={tr('twoFactor.admin.azureMfa')} />
            <p className="ml-6 mt-1 text-xs text-slate-500 dark:text-slate-400">{tr('twoFactor.admin.azureMfaHelp')}</p>
          </div>
        </div>
        <div className="mt-4 flex gap-2">
          <Button variant="primary" size="sm" onClick={save}>
            {tr('admin.azure.save')}
          </Button>
          <Button variant="outline" size="sm" onClick={test}>
            {tr('admin.azure.test')}
          </Button>
        </div>
        {testStatus && (
          <Alert severity={testStatus.status} className="mt-3">
            {testStatus.message}
          </Alert>
        )}
      </SectionCard>

      <SectionCard title={tr('admin.azureGraph.title')}>
        <Checkbox checked={config.graphSearch} onChange={(v) => void setGraphSearch(v)} label={tr('admin.azureGraph.enable')} />
        <p className="ml-6 mt-1 text-xs text-slate-500 dark:text-slate-400">{tr('admin.azureGraph.help')}</p>
        <p className="ml-6 mt-1 text-xs text-slate-500 dark:text-slate-400">
          {tr('admin.azureGraph.permission')} <code className="font-mono text-slate-700 dark:text-slate-300">User.Read.All</code>
        </p>
        <div className="mt-4">
          <Button variant="outline" size="sm" onClick={() => void testGraph()}>
            {tr('admin.azureGraph.test')}
          </Button>
        </div>
        {graphStatus && (
          <Alert severity={graphStatus.status} className="mt-3">
            {graphStatus.message}
          </Alert>
        )}
      </SectionCard>
    </div>
  );
};
