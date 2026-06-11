import type { Credentials, Namespace, LoadBalancer, WAFPolicy, OriginPool, AppType, AppSetting, VirtualSite, UserIdentificationPolicy, AlertReceiver, AlertPolicy, CDNLoadBalancer, CDNCacheRule, IpPrefixSet, ServicePolicy, Certificate } from '../types';

// Proxy endpoint - same server, no need for separate URL
const PROXY_ENDPOINT = '/api/proxy';

class F5XCApiClient {
  private tenant: string | null = null;
  private apiToken: string | null = null;

  init(tenant: string, apiToken: string) {
    this.tenant = tenant;
    this.apiToken = apiToken;
  }

  clear() {
    this.tenant = null;
    this.apiToken = null;
  }

  isInitialized(): boolean {
    return Boolean(this.tenant && this.apiToken);
  }

  getTenant(): string | null {
    return this.tenant;
  }

  getToken(): string | null {
    return this.apiToken;
  }

  private async proxyRequest<T>(endpoint: string, method = 'GET', body?: unknown): Promise<T> {
    if (!this.tenant || !this.apiToken) {
      throw new Error('API client not initialized');
    }

    const response = await fetch(PROXY_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant: this.tenant,
        token: this.apiToken,
        endpoint,
        method,
        body,
      }),
    });

    // Safely parse response — F5 XC API sometimes returns plain text with JSON content-type
    let data;
    const text = await response.text();
    try {
      data = JSON.parse(text);
    } catch {
      // Response body is not valid JSON (rate limit errors, gateway errors, etc.)
      if (!response.ok) {
        const preview = text.length < 200 ? text : text.slice(0, 150) + '...';
        throw new Error(`API Error ${response.status}: ${preview}`);
      }
      return {} as T;
    }

    // Check for HTTP errors or API-specific error fields
    if (!response.ok) {
      // Prioritize specific API error message
      const errorMessage = data.message || data.error || `API Error: ${response.statusText}`;
      throw new Error(errorMessage);
    }
    
    // Some APIs return 200 OK but contain an error field
    if (data.error) {
      throw new Error(data.error);
    }

    return data as T;
  }

  async requestExternal<T>(tenant: string, token: string, endpoint: string, method = 'GET'): Promise<T> {
    const response = await fetch(PROXY_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenant,
        token,
        endpoint,
        method,
      }),
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.message || `External API Error: ${response.statusText}`);
    }

    return response.json();
  }

  static async proxyRequestStatic<T>(tenant: string, token: string, endpoint: string, method = 'GET', body?: unknown): Promise<T> {
    const response = await fetch(PROXY_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenant, token, endpoint, method, body }),
    });

    const text = await response.text();
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      if (!response.ok) {
        const preview = text.length < 200 ? text : text.slice(0, 150) + '...';
        throw new Error(`API Error ${response.status}: ${preview}`);
      }
      return {} as T;
    }

    if (!response.ok) {
      const err = (data as Record<string, string>).message || (data as Record<string, string>).error || `API Error: ${response.statusText}`;
      throw new Error(err);
    }

    return data as T;
  }

  async get<T>(path: string): Promise<T> {
    return this.proxyRequest<T>(path, 'GET');
  }

  async post<T>(path: string, body: unknown): Promise<T> {
    return this.proxyRequest<T>(path, 'POST', body);
  }

  async put<T>(path: string, body: unknown): Promise<T> {
    return this.proxyRequest<T>(path, 'PUT', body);
  }

  async delete<T>(path: string): Promise<T> {
    return this.proxyRequest<T>(path, 'DELETE');
  }

  // --- Namespace APIs ---
  async getNamespaces(): Promise<{ items: Namespace[] }> {
    return this.get('/api/web/namespaces');
  }

  // --- Load Balancer APIs ---
  async getLoadBalancers(namespace: string): Promise<{ items: LoadBalancer[] }> {
    return this.get(`/api/config/namespaces/${namespace}/http_loadbalancers`);
  }

  async getLoadBalancer(namespace: string, name: string): Promise<LoadBalancer> {
    return this.get(`/api/config/namespaces/${namespace}/http_loadbalancers/${name}`);
  }

  async createHttpLoadBalancer(namespace: string, body: unknown): Promise<LoadBalancer> {
    return this.post(`/api/config/namespaces/${namespace}/http_loadbalancers`, body);
  }

  // --- WAF Policy APIs ---
  async getWAFPolicies(namespace: string): Promise<{ items: WAFPolicy[] }> {
    return this.get(`/api/config/namespaces/${namespace}/app_firewalls`);
  }

  async getWAFPolicy(namespace: string, name: string): Promise<WAFPolicy> {
    return this.get(`/api/config/namespaces/${namespace}/app_firewalls/${name}`);
  }

  async createAppFirewall(namespace: string, body: unknown): Promise<any> {
    return this.post(`/api/config/namespaces/${namespace}/app_firewalls`, body);
  }

  // --- Health Check APIs ---
  async getHealthCheck(namespace: string, name: string): Promise<unknown> {
    return this.get(`/api/config/namespaces/${namespace}/healthchecks/${name}`);
  }

  // --- Origin Pool APIs ---
  async getOriginPools(namespace: string): Promise<{ items: OriginPool[] }> {
    return this.get(`/api/config/namespaces/${namespace}/origin_pools`);
  }

  async getOriginPool(namespace: string, name: string): Promise<OriginPool> {
    return this.get(`/api/config/namespaces/${namespace}/origin_pools/${name}`);
  }

  async createOriginPool(namespace: string, body: unknown): Promise<OriginPool> {
    return this.post(`/api/config/namespaces/${namespace}/origin_pools`, body);
  }

  // --- App Types APIs ---
  async getAppTypes(namespace: string): Promise<{ items: AppType[] }> {
    return this.get(`/api/config/namespaces/${namespace}/app_types`);
  }

  async getAppType(name: string): Promise<AppType> {
    return this.get(`/api/config/namespaces/shared/app_types/${name}`);
  }

  // --- App Settings APIs ---
  async getAppSettings(namespace: string): Promise<{ items: AppSetting[] }> {
    return this.get(`/api/config/namespaces/${namespace}/app_settings`);
  }

  // --- Virtual Site APIs ---
  async getVirtualSites(namespace: string): Promise<{ items: VirtualSite[] }> {
    return this.get(`/api/config/namespaces/${namespace}/virtual_sites`);
  }

  async getVirtualSite(namespace: string, name: string): Promise<VirtualSite> {
    return this.get(`/api/config/namespaces/${namespace}/virtual_sites/${name}`);
  }

  // --- User Identification APIs ---
  async getUserIdentificationPolicies(namespace: string): Promise<{ items: UserIdentificationPolicy[] }> {
    return this.get(`/api/config/namespaces/${namespace}/user_identification_policys`);
  }

  async getUserIdentificationPolicy(namespace: string, name: string): Promise<UserIdentificationPolicy> {
    return this.get(`/api/config/namespaces/${namespace}/user_identifications/${name}`);
  }

  // --- CDN APIs ---
  async getCDNLoadBalancers(namespace: string): Promise<{ items: CDNLoadBalancer[] }> {
    return this.get(`/api/config/namespaces/${namespace}/cdn_loadbalancers`);
  }

  async getCDNs(namespace: string): Promise<{ items: CDNLoadBalancer[] }> {
    return this.getCDNLoadBalancers(namespace);
  }

  async getCDN(namespace: string, name: string): Promise<CDNLoadBalancer> {
    return this.get(`/api/config/namespaces/${namespace}/cdn_loadbalancers/${name}`);
  }

  async getCDNCacheRules(namespace: string): Promise<{ items: CDNCacheRule[] }> {
    return this.get(`/api/config/namespaces/${namespace}/cdn_cache_rules`);
  }

  async getCDNCacheRule(namespace: string, name: string): Promise<CDNCacheRule> {
    return this.get(`/api/config/namespaces/${namespace}/cdn_cache_rules/${name}`);
  }

  // --- Alert Receiver APIs ---
  async getAlertReceivers(namespace: string): Promise<{ items: AlertReceiver[] }> {
    return this.get(`/api/config/namespaces/${namespace}/alert_receivers`);
  }

  async getAlertReceiver(namespace: string, name: string): Promise<AlertReceiver> {
    return this.get(`/api/config/namespaces/${namespace}/alert_receivers/${name}`);
  }

  async createAlertReceiver(namespace: string, body: unknown): Promise<AlertReceiver> {
    return this.post(`/api/config/namespaces/${namespace}/alert_receivers`, body);
  }

  // --- Alert Policy APIs ---
  async getAlertPolicies(namespace: string): Promise<{ items: AlertPolicy[] }> {
    return this.get(`/api/config/namespaces/${namespace}/alert_policys`);
  }

  async getAlertPolicy(namespace: string, name: string): Promise<AlertPolicy> {
    return this.get(`/api/config/namespaces/${namespace}/alert_policys/${name}`);
  }

  async createAlertPolicy(namespace: string, body: unknown): Promise<AlertPolicy> {
    return this.post(`/api/config/namespaces/${namespace}/alert_policys`, body);
  }

  // --- Service Policy APIs ---
  async getServicePolicies(namespace: string): Promise<{ items: ServicePolicy[] }> {
    return this.get(`/api/config/namespaces/${namespace}/service_policys`);
  }

  async getServicePolicy(namespace: string, name: string): Promise<ServicePolicy> {
    return this.get(`/api/config/namespaces/${namespace}/service_policys/${name}`);
  }

  async updateServicePolicy(namespace: string, name: string, body: unknown): Promise<ServicePolicy> {
    return this.put(`/api/config/namespaces/${namespace}/service_policys/${name}`, body);
  }

  async createServicePolicy(namespace: string, body: unknown): Promise<ServicePolicy> {
    return this.post(`/api/config/namespaces/${namespace}/service_policys`, body);
  }

  // --- IP Prefix Set APIs ---
  async getIpPrefixSets(namespace: string): Promise<{ items: IpPrefixSet[] }> {
    return this.get(`/api/config/namespaces/${namespace}/ip_prefix_sets`);
  }

  async getIpPrefixSet(namespace: string, name: string): Promise<IpPrefixSet> {
    return this.get(`/api/config/namespaces/${namespace}/ip_prefix_sets/${name}`);
  }

  async createIpPrefixSet(namespace: string, body: unknown): Promise<IpPrefixSet> {
    return this.post(`/api/config/namespaces/${namespace}/ip_prefix_sets`, body);
  }

  // --- Certificate APIs ---
  async getCertificates(namespace: string): Promise<{ items: Certificate[] }> {
    return this.get(`/api/config/namespaces/${namespace}/certificates`);
  }

  // --- Access Logs APIs (for Rate Limit Advisor) ---
  async getAccessLogs(namespace: string, body: unknown): Promise<unknown> {
    return this.post(`/api/data/namespaces/${namespace}/access_logs`, body);
  }

  async scrollAccessLogs(namespace: string, body: { scroll_id: string; namespace: string }): Promise<unknown> {
    return this.post(`/api/data/namespaces/${namespace}/access_logs/scroll`, body);
  }

  // --- Security Events APIs ---
  async getSecurityEvents(namespace: string, body: unknown): Promise<unknown> {
    return this.post(`/api/data/namespaces/${namespace}/app_security/events`, body);
  }

  async scrollSecurityEvents(namespace: string, body: { scroll_id: string; namespace: string }): Promise<unknown> {
    return this.post(`/api/data/namespaces/${namespace}/app_security/events/scroll`, body);
  }

  // --- Rate Limiter APIs ---
  async getRateLimiters(namespace: string): Promise<{ items: unknown[] }> {
    return this.get(`/api/config/namespaces/${namespace}/rate_limiters`);
  }

  async createRateLimiter(namespace: string, body: unknown): Promise<unknown> {
    return this.post(`/api/config/namespaces/${namespace}/rate_limiters`, body);
  }

  // --- Rate Limiter Policy APIs ---
  async getRateLimiterPolicies(namespace: string): Promise<{ items: unknown[] }> {
    return this.get(`/api/config/namespaces/${namespace}/rate_limiter_policys`);
  }

  async createRateLimiterPolicy(namespace: string, body: unknown): Promise<unknown> {
    return this.post(`/api/config/namespaces/${namespace}/rate_limiter_policys`, body);
  }

  // --- WAF Exclusion Policy APIs ---
  async listWafExclusionPolicies(namespace: string): Promise<{ items: unknown[] }> {
    return this.get(`/api/config/namespaces/${namespace}/waf_exclusion_policys`);
  }

  async getWafExclusionPolicy(namespace: string, name: string): Promise<unknown> {
    return this.get(`/api/config/namespaces/${namespace}/waf_exclusion_policys/${name}`);
  }

  async createWafExclusionPolicy(namespace: string, body: unknown): Promise<unknown> {
    return this.post(`/api/config/namespaces/${namespace}/waf_exclusion_policys`, body);
  }

  async replaceWafExclusionPolicy(namespace: string, name: string, body: unknown): Promise<unknown> {
    return this.put(`/api/config/namespaces/${namespace}/waf_exclusion_policys/${name}`, body);
  }

  async deleteWafExclusionPolicy(namespace: string, name: string): Promise<unknown> {
    return this.delete(`/api/config/namespaces/${namespace}/waf_exclusion_policys/${name}`);
  }
}

export { F5XCApiClient };
export const apiClient = new F5XCApiClient();

const STORAGE_KEY = 'xc_bulkops_credentials';

export const storageManager = {
  saveCredentials(credentials: Credentials) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(credentials));
  },

  loadCredentials(): Credentials | null {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  },

  clearCredentials() {
    localStorage.removeItem(STORAGE_KEY);
  },
};