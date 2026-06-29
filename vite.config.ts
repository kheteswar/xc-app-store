import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fpAnalyzerPlugin } from './server/fp-analyzer-plugin';
import type { IncomingMessage, ServerResponse } from 'http';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import tls from 'node:tls';

/**
 * Handle load test proxy requests — forwards to target URL and measures response time
 */
async function handleLoadTestRequest(req: IncomingMessage, res: ServerResponse) {
  let body = '';
  for await (const chunk of req) body += chunk;

  try {
    const { url: targetUrl, method = 'GET', headers: customHeaders = {}, body: reqBody } = JSON.parse(body);
    if (!targetUrl) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing url' }));
      return;
    }

    const urlObj = new URL(targetUrl);
    const isHttps = urlObj.protocol === 'https:';
    const httpModule = isHttps ? https : http;
    const startTime = Date.now();

    const options: any = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method,
      headers: { ...customHeaders, Host: urlObj.hostname },
      timeout: 30000,
    };
    if (isHttps) options.rejectUnauthorized = false;

    const proxyReq = httpModule.request(options, (proxyRes) => {
      let bodySize = 0;
      proxyRes.on('data', (chunk: Buffer) => { bodySize += chunk.length; });
      proxyRes.on('end', () => {
        const responseTimeMs = Date.now() - startTime;
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ statusCode: proxyRes.statusCode || 0, responseTimeMs, bodySize }));
      });
    });

    proxyReq.on('error', (err: any) => {
      if (!res.headersSent) {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ statusCode: 0, responseTimeMs: Date.now() - startTime, bodySize: 0, error: err.message }));
      }
    });

    proxyReq.on('timeout', () => {
      proxyReq.destroy();
      if (!res.headersSent) {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ statusCode: 0, responseTimeMs: Date.now() - startTime, bodySize: 0, error: 'Request timeout (30s)' }));
      }
    });

    if (reqBody && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
      proxyReq.write(typeof reqBody === 'string' ? reqBody : JSON.stringify(reqBody));
    }
    proxyReq.end();

  } catch (err: any) {
    if (!res.headersSent) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
  }
}

/**
 * Make HTTPS request to F5 XC API (and External APIs)
 * Used by the generic /api/proxy endpoint
 */
function makeF5XCRequest(options: https.RequestOptions, postData?: string): Promise<{
  statusCode: number;
  body: string;
}> {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode || 500,
          body: data,
        });
      });
    });
    
    req.on('error', reject);
    req.setTimeout(60000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

/**
 * Make HTTPS request that returns raw Buffer (for binary endpoints like ZIP downloads)
 */
function makeF5XCRequestRaw(options: https.RequestOptions, postData?: string): Promise<{
  statusCode: number;
  body: Buffer;
}> {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => { chunks.push(chunk); });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode || 500,
          body: Buffer.concat(chunks),
        });
      });
    });
    req.on('error', reject);
    req.setTimeout(60000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    if (postData) req.write(postData);
    req.end();
  });
}

/**
 * Parse ZIP buffer — extract files (handles STORE and DEFLATE methods).
 *
 * F5 XC streams the swagger_spec ZIP with bit-3 of the general-purpose flag set,
 * which leaves compressedSize=0 in the local file header. The authoritative
 * sizes live in the Central Directory at the end of the file, so we parse
 * that first and use the local header offsets it provides.
 */
function parseZipBuffer(buffer: Buffer): Array<{ filename: string; data: Buffer }> {
  const files: Array<{ filename: string; data: Buffer }> = [];

  // 1. Locate the End of Central Directory Record (EOCD), scanning backward.
  //    EOCD signature = 0x06054b50, comment field is up to 65535 bytes.
  const EOCD_SIG = 0x06054b50;
  const CDH_SIG = 0x02014b50;
  const LFH_SIG = 0x04034b50;

  let eocdOffset = -1;
  const minScan = Math.max(0, buffer.length - 65557);
  for (let i = buffer.length - 22; i >= minScan; i--) {
    if (buffer.readUInt32LE(i) === EOCD_SIG) {
      eocdOffset = i;
      break;
    }
  }

  if (eocdOffset === -1) {
    // Fallback: try the original local-header walk for non-streaming ZIPs.
    return parseZipBufferLinear(buffer);
  }

  const cdSize = buffer.readUInt32LE(eocdOffset + 12);
  const cdOffset = buffer.readUInt32LE(eocdOffset + 16);
  if (cdOffset + cdSize > buffer.length) return parseZipBufferLinear(buffer);

  // 2. Walk the Central Directory.
  let p = cdOffset;
  while (p + 46 <= cdOffset + cdSize) {
    if (buffer.readUInt32LE(p) !== CDH_SIG) break;

    const compressionMethod = buffer.readUInt16LE(p + 10);
    const compressedSize = buffer.readUInt32LE(p + 20);
    const filenameLen = buffer.readUInt16LE(p + 28);
    const extraLen = buffer.readUInt16LE(p + 30);
    const commentLen = buffer.readUInt16LE(p + 32);
    const localHeaderOffset = buffer.readUInt32LE(p + 42);
    const filename = buffer.toString('utf8', p + 46, p + 46 + filenameLen);
    p += 46 + filenameLen + extraLen + commentLen;

    // 3. Resolve the actual data start using the local file header.
    if (localHeaderOffset + 30 > buffer.length) continue;
    if (buffer.readUInt32LE(localHeaderOffset) !== LFH_SIG) continue;
    const lfhFnameLen = buffer.readUInt16LE(localHeaderOffset + 26);
    const lfhExtraLen = buffer.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + lfhFnameLen + lfhExtraLen;
    if (dataStart + compressedSize > buffer.length) continue;

    const compressedData = buffer.slice(dataStart, dataStart + compressedSize);

    try {
      let data: Buffer;
      if (compressionMethod === 0) {
        data = compressedData;
      } else if (compressionMethod === 8) {
        data = zlib.inflateRawSync(compressedData);
      } else {
        continue;
      }
      files.push({ filename, data });
    } catch {
      // skip corrupt entry
    }
  }

  return files;
}

/** Linear scan of local file headers — only works when compressedSize is set in LFH. */
function parseZipBufferLinear(buffer: Buffer): Array<{ filename: string; data: Buffer }> {
  const files: Array<{ filename: string; data: Buffer }> = [];
  let offset = 0;
  while (offset + 30 <= buffer.length) {
    const sig = buffer.readUInt32LE(offset);
    if (sig !== 0x04034b50) break;
    const compressionMethod = buffer.readUInt16LE(offset + 8);
    const compressedSize = buffer.readUInt32LE(offset + 18);
    const filenameLength = buffer.readUInt16LE(offset + 26);
    const extraLength = buffer.readUInt16LE(offset + 28);
    const filename = buffer.toString('utf8', offset + 30, offset + 30 + filenameLength);
    const dataStart = offset + 30 + filenameLength + extraLength;
    const compressedData = buffer.slice(dataStart, dataStart + compressedSize);
    try {
      let data: Buffer;
      if (compressionMethod === 0) data = compressedData;
      else if (compressionMethod === 8) data = zlib.inflateRawSync(compressedData);
      else { offset = dataStart + compressedSize; continue; }
      files.push({ filename, data });
    } catch { /* skip */ }
    offset = dataStart + compressedSize;
  }
  return files;
}

/**
 * Handle swagger-parse requests: download ZIP, extract JSONs, return parsed specs
 */
async function handleSwaggerParse(req: IncomingMessage, res: ServerResponse) {
  let body = '';
  for await (const chunk of req) body += chunk;

  try {
    const { tenant, token, namespace, lbName } = JSON.parse(body);
    if (!tenant || !token || !namespace || !lbName) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing required fields' }));
      return;
    }

    const hostname = `${tenant}.console.ves.volterra.io`;
    const path = `/api/ml/data/namespaces/${namespace}/virtual_hosts/ves-io-http-loadbalancer-${lbName}/api_endpoints/swagger_spec`;

    console.log(`[SwaggerParse] Downloading spec for ${lbName} from ${hostname}${path}`);

    const response = await makeF5XCRequestRaw({
      hostname,
      path,
      method: 'GET',
      headers: {
        'Authorization': `APIToken ${token}`,
        'Accept': '*/*',
      },
    });

    if (response.statusCode !== 200) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: `API Discovery may not be enabled (HTTP ${response.statusCode})`,
        specs: [],
      }));
      return;
    }

    // Parse the ZIP and extract JSON files
    const sigHex = response.body.length >= 4
      ? response.body.slice(0, 4).toString('hex')
      : '(empty)';
    const files = parseZipBuffer(response.body);
    const jsonFiles = files.filter((f) => f.filename.endsWith('.json'));
    console.log(`[SwaggerParse] ${lbName}: ${response.body.length} bytes, sig=${sigHex}, ${files.length} files, ${jsonFiles.length} JSON`);

    const specs: Array<{
      filename: string;
      fqdn: string;
      title?: string;
      version?: string;
      description?: string;
      openapi?: string;
      raw: any;
      endpoints: Array<{
        path: string;
        method: string;
        contentType: string;
        summary?: string;
        description?: string;
        tags?: string[];
        deprecated?: boolean;
        operationId?: string;
        parameters?: Array<{ name: string; in: string; required?: boolean; type?: string; description?: string }>;
        requestBody?: { contentTypes: string[]; required?: boolean; schemaSummary?: string };
        responses?: Array<{ code: string; description?: string; contentTypes?: string[] }>;
        security?: string[];
      }>;
    }> = [];

    function summarizeSchema(schema: any): string {
      if (!schema || typeof schema !== 'object') return '';
      if (schema.$ref) return schema.$ref.split('/').pop() || schema.$ref;
      if (schema.type === 'array' && schema.items) return `array<${summarizeSchema(schema.items) || 'any'}>`;
      if (schema.type) return schema.type;
      if (schema.properties) return `object{${Object.keys(schema.properties).slice(0, 6).join(',')}${Object.keys(schema.properties).length > 6 ? '…' : ''}}`;
      return '';
    }

    for (const file of jsonFiles) {
      try {
        const spec = JSON.parse(file.data.toString('utf8'));
        const servers = spec.servers || [];
        const fqdn = servers.map((s: any) => s.url || '').join(', ');
        const paths = spec.paths || {};
        const endpoints: typeof specs[number]['endpoints'] = [];

        for (const [pathKey, pathDetails] of Object.entries(paths)) {
          const pathItem = pathDetails as Record<string, any>;
          const sharedParams = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];
          for (const [method, methodDetails] of Object.entries(pathItem)) {
            if (!['get', 'post', 'put', 'delete', 'patch', 'options', 'head'].includes(method.toLowerCase())) continue;
            const op = methodDetails as Record<string, any>;

            let contentType = '-';
            let requestBody: { contentTypes: string[]; required?: boolean; schemaSummary?: string } | undefined;
            if (op.requestBody?.content) {
              const ctKeys = Object.keys(op.requestBody.content);
              contentType = ctKeys.join(', ');
              const firstCt = ctKeys[0];
              const schemaSummary = firstCt ? summarizeSchema(op.requestBody.content[firstCt]?.schema) : '';
              requestBody = {
                contentTypes: ctKeys,
                required: op.requestBody.required,
                schemaSummary,
              };
            }

            const opParams = Array.isArray(op.parameters) ? op.parameters : [];
            const allParams = [...sharedParams, ...opParams];
            const parameters = allParams.map((p: any) => ({
              name: p.name,
              in: p.in,
              required: p.required,
              type: summarizeSchema(p.schema) || p.type,
              description: p.description,
            }));

            const responses = op.responses
              ? Object.entries(op.responses).map(([code, resp]: [string, any]) => ({
                  code,
                  description: resp?.description,
                  contentTypes: resp?.content ? Object.keys(resp.content) : undefined,
                }))
              : undefined;

            const security = Array.isArray(op.security)
              ? op.security.flatMap((s: any) => Object.keys(s || {}))
              : undefined;

            endpoints.push({
              path: pathKey,
              method: method.toUpperCase(),
              contentType,
              summary: op.summary,
              description: op.description,
              tags: op.tags,
              deprecated: op.deprecated,
              operationId: op.operationId,
              parameters: parameters.length > 0 ? parameters : undefined,
              requestBody,
              responses,
              security: security && security.length > 0 ? security : undefined,
            });
          }
        }

        specs.push({
          filename: file.filename,
          fqdn,
          title: spec.info?.title,
          version: spec.info?.version,
          description: spec.info?.description,
          openapi: spec.openapi || spec.swagger,
          raw: spec,
          endpoints,
        });
      } catch {
        // Skip unparseable JSON
      }
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ specs }));

  } catch (err: any) {
    console.error('[SwaggerParse] Error:', err.message);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: err.message }));
  }
}

/**
 * Handle raw swagger-zip download — streams the F5 XC swagger_spec ZIP back
 * to the browser as application/zip so the user can save the original file
 * (same content as F5 XC console "Download Schema").
 */
async function handleSwaggerZip(req: IncomingMessage, res: ServerResponse) {
  let body = '';
  for await (const chunk of req) body += chunk;

  try {
    const { tenant, token, namespace, lbName } = JSON.parse(body);
    if (!tenant || !token || !namespace || !lbName) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing required fields' }));
      return;
    }

    const hostname = `${tenant}.console.ves.volterra.io`;
    const path = `/api/ml/data/namespaces/${namespace}/virtual_hosts/ves-io-http-loadbalancer-${lbName}/api_endpoints/swagger_spec`;

    console.log(`[SwaggerZip] Downloading raw schema for ${lbName} from ${hostname}${path}`);

    const response = await makeF5XCRequestRaw({
      hostname,
      path,
      method: 'GET',
      headers: {
        'Authorization': `APIToken ${token}`,
        'Accept': '*/*',
      },
    });

    if (response.statusCode !== 200) {
      res.writeHead(response.statusCode, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `F5 XC returned HTTP ${response.statusCode} — API Discovery may not be enabled for ${lbName}` }));
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'application/zip',
      'Content-Length': response.body.length.toString(),
      'Content-Disposition': `attachment; filename="${lbName}_swagger_spec.zip"`,
      'Access-Control-Allow-Origin': '*',
    });
    res.end(response.body);
  } catch (err: any) {
    console.error('[SwaggerZip] Error:', err.message);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: err.message }));
  }
}

/**
 * Handle generic proxy requests to F5 XC API & External APIs
 * Used by WAF Scanner, Security Auditor, Time Tracker, etc.
 */
async function handleProxyRequest(req: IncomingMessage, res: ServerResponse) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
  }

  try {
    const parsed = JSON.parse(body);
    const { tenant, token, endpoint, method = 'GET', body: requestBody, isExternal, targetUrl } = parsed;

    if (!token) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing token' }));
      return;
    }

    let hostname = '';
    let path = '';
    let authHeader = '';

    // NEW: Handle External APIs (like Time Tracker) differently
    if (isExternal && targetUrl) {
      const urlObj = new URL(targetUrl);
      hostname = urlObj.hostname;
      path = urlObj.pathname + urlObj.search;
      authHeader = `Bearer ${token}`; // External APIs typically use Bearer
    } else {
      // EXISTING: Standard F5 XC formatting
      if (!tenant || !endpoint) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing tenant or endpoint for F5 XC request' }));
        return;
      }
      hostname = `${tenant}.console.ves.volterra.io`;
      path = endpoint.startsWith('/api') ? endpoint : `/api${endpoint}`;
      authHeader = `APIToken ${token}`; // F5 XC requires APIToken prefix
    }

    const options: https.RequestOptions = {
      hostname: hostname,
      path: path,
      method: method,
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    };

    const response = await makeF5XCRequest(options, requestBody ? JSON.stringify(requestBody) : undefined);

    res.writeHead(response.statusCode, { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*' 
    });
    res.end(response.body);

  } catch (error: any) {
    console.error('Proxy error:', error);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: error.message }));
  }
}

/**
 * Extract TLS certificate details from an HTTPS socket
 */
function extractCertInfo(socket: tls.TLSSocket | null): Record<string, any> | null {
  if (!socket || typeof socket.getPeerCertificate !== 'function') return null;
  try {
    const cert = socket.getPeerCertificate(false);
    if (!cert || !cert.subject) return null;
    return {
      subject: cert.subject?.CN || '',
      issuer: cert.issuer?.CN || '',
      issuerOrg: cert.issuer?.O || '',
      validFrom: cert.valid_from || '',
      validTo: cert.valid_to || '',
      serialNumber: cert.serialNumber || '',
      fingerprint256: cert.fingerprint256 || '',
      subjectAltName: cert.subjectaltname || '',
      protocol: socket.getProtocol?.() || '',
    };
  } catch {
    return null;
  }
}

export default defineConfig({
  plugins: [
    react(),
    fpAnalyzerPlugin(),
    {
      name: 'f5xc-proxy',
      configureServer(server) {

        // -------------------------------------------------------------
        // 1. Sanity Checker Proxy (Specific Route)
        //    Handles "Live vs Spoof" requests with custom DNS logic
        // -------------------------------------------------------------
        server.middlewares.use('/api/proxy/request', (req, res, next) => {
          if (req.method !== 'POST') return next();

          let body = '';
          req.on('data', chunk => body += chunk);
          req.on('end', async () => {
            try {
              if (!body) throw new Error('Empty request body');
              const parsed = JSON.parse(body);
              
              // Destructure and validate
              const { url: targetUrl, method = 'GET', headers = {}, targetIp, body: reqBody } = parsed;

              if (!targetUrl) throw new Error('Missing URL parameter');

              // Serialize an optional request body (used by the WAF Attack Simulator
              // to deliver payloads in POST/PUT bodies). Strings are sent verbatim;
              // objects are JSON-encoded. Content-Length is set so origins/WAFs that
              // reject chunked bodies still see the payload.
              const outgoingBody =
                reqBody === undefined || reqBody === null
                  ? undefined
                  : typeof reqBody === 'string'
                  ? reqBody
                  : JSON.stringify(reqBody);
              const bodyHeaders: Record<string, string> = {};
              if (outgoingBody !== undefined) {
                const hasCL = Object.keys(headers).some((h) => h.toLowerCase() === 'content-length');
                if (!hasCL) bodyHeaders['Content-Length'] = String(Buffer.byteLength(outgoingBody));
              }

              console.log(`[SanityProxy] ${method} ${targetUrl}`);
              console.log(`[SanityProxy] Raw targetIp:`, targetIp, `(type: ${typeof targetIp})`);

              const urlObj = new URL(targetUrl);
              const isHttps = urlObj.protocol === 'https:';
              
              // If we have a valid targetIp (not null, undefined, or empty), we need to spoof DNS
              const shouldSpoof = targetIp && typeof targetIp === 'string' && targetIp.trim().length > 0;
              
              if (shouldSpoof) {
                console.log(`[SanityProxy] Spoofing ${urlObj.hostname} -> ${targetIp}`);
                
                // For spoofed requests, we connect directly to the IP but use proper headers
                const spoofOptions: any = {
                  host: targetIp, // Connect to this IP
                  hostname: targetIp,
                  port: isHttps ? 443 : 80,
                  path: urlObj.pathname + urlObj.search,
                  method,
                  headers: {
                    ...headers,
                    ...bodyHeaders,
                    // Ensure Host header is set to the original hostname
                    'Host': headers['Host'] || urlObj.hostname
                  },
                  rejectUnauthorized: false, // Allow self-signed certs
                  servername: urlObj.hostname, // SNI for HTTPS
                  timeout: 15000
                };

                const httpModule = isHttps ? https : http;
                const proxyReq = httpModule.request(spoofOptions, (proxyRes) => {
                  // Extract TLS certificate info from the socket
                  const tlsCert = isHttps
                    ? extractCertInfo((proxyReq.socket as tls.TLSSocket) || null)
                    : null;

                  const chunks: Buffer[] = [];
                  let bodySize = 0;
                  const maxBodySize = 10 * 1024 * 1024; // 10MB limit

                  // Handle compression
                  let responseStream = proxyRes;
                  const encoding = proxyRes.headers['content-encoding'];

                  if (encoding === 'gzip') {
                    responseStream = proxyRes.pipe(zlib.createGunzip());
                  } else if (encoding === 'deflate') {
                    responseStream = proxyRes.pipe(zlib.createInflate());
                  } else if (encoding === 'br') {
                    responseStream = proxyRes.pipe(zlib.createBrotliDecompress());
                  }

                  responseStream.on('data', (chunk: Buffer) => {
                    bodySize += chunk.length;
                    if (bodySize > maxBodySize) {
                      proxyReq.destroy();
                      console.error(`[SanityProxy] Response too large: ${bodySize} bytes`);
                      return;
                    }
                    chunks.push(chunk);
                  });

                  responseStream.on('end', () => {
                    const buffer = Buffer.concat(chunks);
                    const resBody = buffer.toString('utf-8');
                    console.log(`[SanityProxy] Spoofed response: ${proxyRes.statusCode} (${bodySize} bytes, encoding: ${encoding || 'none'})`);
                    const responseData = {
                      status: proxyRes.statusCode,
                      statusText: proxyRes.statusMessage,
                      headers: proxyRes.headers,
                      body: resBody,
                      connectedIp: targetIp, // The IP we connected to
                      tlsCert,
                    };
                    console.log(`[SanityProxy] Sending to frontend - connectedIp: ${responseData.connectedIp}`);
                    res.writeHead(200, {
                      'Content-Type': 'application/json',
                      'Access-Control-Allow-Origin': '*'
                    });
                    res.end(JSON.stringify(responseData));
                  });

                  responseStream.on('error', (err: any) => {
                    console.error(`[SanityProxy] Decompression error:`, err.message);
                    if (!res.headersSent) {
                      res.writeHead(502, { 'Content-Type': 'application/json' });
                      res.end(JSON.stringify({ error: `Decompression Error: ${err.message}` }));
                    }
                  });
                });

                proxyReq.on('timeout', () => {
                  console.error(`[SanityProxy] Request timeout after 15s`);
                  proxyReq.destroy();
                  if (!res.headersSent) {
                    res.writeHead(504, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Request timeout after 15 seconds' }));
                  }
                });

                proxyReq.on('error', (err: any) => {
                  console.error(`[SanityProxy] Spoofed Request Error:`, err.message);
                  if (!res.headersSent) {
                    res.writeHead(502, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: `Spoofed Connection Failed: ${err.message}` }));
                  }
                });

                if (outgoingBody !== undefined) proxyReq.write(outgoingBody);
                proxyReq.end();
              } else {
                // Live DNS request - use Google DNS resolver to bypass local /etc/hosts
                console.log(`[SanityProxy] Live DNS request to ${targetUrl}`);
                
                // Use Google DNS (8.8.8.8) for resolution
                const dnsResolver = new dns.promises.Resolver();
                dnsResolver.setServers(['8.8.8.8', '8.8.4.4']); // Google DNS servers
                
                // Resolve the hostname using Google DNS
                let resolvedIp: string;
                try {
                  const addresses = await dnsResolver.resolve4(urlObj.hostname);
                  resolvedIp = addresses[0];
                  console.log(`[SanityProxy] Google DNS resolved ${urlObj.hostname} -> ${resolvedIp}`);
                } catch (dnsError: any) {
                  console.error(`[SanityProxy] DNS resolution failed:`, dnsError.message);
                  throw new Error(`DNS resolution failed: ${dnsError.message}`);
                }
                
                // Now connect to the resolved IP
                const liveOptions: any = {
                  host: resolvedIp, // Connect to the Google DNS resolved IP
                  hostname: resolvedIp,
                  port: isHttps ? 443 : 80,
                  path: urlObj.pathname + urlObj.search,
                  method,
                  headers: {
                    ...headers,
                    ...bodyHeaders,
                    'Host': urlObj.hostname // Keep original hostname in Host header
                  },
                  servername: urlObj.hostname, // SNI for HTTPS
                  rejectUnauthorized: false,
                  timeout: 15000
                };

                const httpModule = isHttps ? https : http;
                const proxyReq = httpModule.request(liveOptions, (proxyRes) => {
                  // Use the resolved IP as the connected IP
                  const connectedIp = resolvedIp;

                  // Extract TLS certificate info from the socket
                  const tlsCert = isHttps
                    ? extractCertInfo((proxyReq.socket as tls.TLSSocket) || null)
                    : null;

                  const chunks: Buffer[] = [];
                  let bodySize = 0;
                  const maxBodySize = 10 * 1024 * 1024; // 10MB limit

                  // Handle compression
                  let responseStream = proxyRes;
                  const encoding = proxyRes.headers['content-encoding'];

                  if (encoding === 'gzip') {
                    responseStream = proxyRes.pipe(zlib.createGunzip());
                  } else if (encoding === 'deflate') {
                    responseStream = proxyRes.pipe(zlib.createInflate());
                  } else if (encoding === 'br') {
                    responseStream = proxyRes.pipe(zlib.createBrotliDecompress());
                  }

                  responseStream.on('data', (chunk: Buffer) => {
                    bodySize += chunk.length;
                    if (bodySize > maxBodySize) {
                      proxyReq.destroy();
                      console.error(`[SanityProxy] Response too large: ${bodySize} bytes`);
                      return;
                    }
                    chunks.push(chunk);
                  });

                  responseStream.on('end', () => {
                    const buffer = Buffer.concat(chunks);
                    const resBody = buffer.toString('utf-8');
                    console.log(`[SanityProxy] Live response: ${proxyRes.statusCode} (${bodySize} bytes, encoding: ${encoding || 'none'}, IP: ${connectedIp})`);
                    const responseData = {
                      status: proxyRes.statusCode,
                      statusText: proxyRes.statusMessage,
                      headers: proxyRes.headers,
                      body: resBody,
                      connectedIp: connectedIp, // The actual IP we connected to
                      tlsCert,
                    };
                    console.log(`[SanityProxy] Sending to frontend - connectedIp: ${responseData.connectedIp}`);
                    res.writeHead(200, {
                      'Content-Type': 'application/json',
                      'Access-Control-Allow-Origin': '*'
                    });
                    res.end(JSON.stringify(responseData));
                  });

                  responseStream.on('error', (err: any) => {
                    console.error(`[SanityProxy] Decompression error:`, err.message);
                    if (!res.headersSent) {
                      res.writeHead(502, { 'Content-Type': 'application/json' });
                      res.end(JSON.stringify({ error: `Decompression Error: ${err.message}` }));
                    }
                  });
                });

                proxyReq.on('timeout', () => {
                  console.error(`[SanityProxy] Request timeout after 15s`);
                  proxyReq.destroy();
                  if (!res.headersSent) {
                    res.writeHead(504, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Request timeout after 15 seconds' }));
                  }
                });

                proxyReq.on('error', (err: any) => {
                  console.error(`[SanityProxy] Live Request Error:`, err.message);
                  if (!res.headersSent) {
                    res.writeHead(502, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: `Live Connection Failed: ${err.message}` }));
                  }
                });

                if (outgoingBody !== undefined) proxyReq.write(outgoingBody);
                proxyReq.end();
              }
            } catch (e: any) {
              console.error(`[SanityProxy] Parse Error:`, e.message);
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: `Invalid Request: ${e.message}` }));
            }
          });
        });

        // -------------------------------------------------------------
        // 2. Swagger Parse Proxy (ZIP download + parse)
        //    Downloads swagger spec ZIP, extracts JSONs, returns parsed specs
        // -------------------------------------------------------------
        server.middlewares.use('/api/proxy/swagger-parse', (req, res, next) => {
          if (req.method === 'OPTIONS') {
            res.writeHead(200, {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type',
            });
            res.end();
            return;
          }
          if (req.method !== 'POST') return next();
          handleSwaggerParse(req, res);
        });

        // -------------------------------------------------------------
        // 2b. Swagger Zip Proxy (raw ZIP download)
        //     Streams the F5 XC swagger_spec ZIP back to the client so
        //     it can be saved exactly like the console's "Download Schema"
        // -------------------------------------------------------------
        server.middlewares.use('/api/proxy/swagger-zip', (req, res, next) => {
          if (req.method === 'OPTIONS') {
            res.writeHead(200, {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type',
            });
            res.end();
            return;
          }
          if (req.method !== 'POST') return next();
          handleSwaggerZip(req, res);
        });

        // -------------------------------------------------------------
        // 3. Generic F5 XC Proxy (General Route)
        //    Handles standard API calls for other tools
        // -------------------------------------------------------------
        server.middlewares.use('/api/proxy', (req, res, next) => {
          // IMPORTANT: If the URL matches the specific route above, do NOT process it here.
          // Note: req.originalUrl includes the full path, req.url is relative to mount point
          if (req.originalUrl && (
            req.originalUrl.includes('/api/proxy/request') ||
            req.originalUrl.includes('/api/proxy/swagger-parse') ||
            req.originalUrl.includes('/api/proxy/swagger-zip')
          )) {
            return next();
          }

          if (req.method === 'POST') {
            handleProxyRequest(req, res);
          } else if (req.method === 'OPTIONS') {
            res.writeHead(200, {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type',
            });
            res.end();
          } else {
            next();
          }
        });

        // -------------------------------------------------------------
        // 3. Health Check
        // -------------------------------------------------------------
        server.middlewares.use('/api/health', (req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }));
        });

        // -------------------------------------------------------------
        // 4. Load Tester Proxy
        // -------------------------------------------------------------
        server.middlewares.use('/api/load-test', (req, res, next) => {
          if (req.method === 'OPTIONS') {
            res.writeHead(200, {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type',
            });
            res.end();
            return;
          }
          if (req.method !== 'POST') return next();
          handleLoadTestRequest(req, res);
        });

        console.log('\n 🔌 F5 XC API Proxy enabled at /api/proxy');
        console.log(' 🔌 Sanity Checker Proxy enabled at /api/proxy/request');
        console.log(' 🔌 Swagger Parse Proxy enabled at /api/proxy/swagger-parse');
        console.log(' 🔌 Swagger Zip Proxy enabled at /api/proxy/swagger-zip');
        console.log(' 🔌 Load Tester Proxy enabled at /api/load-test\n');
      },
    },
  ],
  server: {
    port: 5173,
    open: true,
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});