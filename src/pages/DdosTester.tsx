import { useState, useRef, useCallback, useMemo, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft, ShieldAlert, Server, Play, Square, Download, Copy, Check,
  Zap, Activity, AlertTriangle, HeartPulse, Rocket, Terminal, Gauge,
} from 'lucide-react';
import {
  ComposedChart, Area, Line, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer,
} from 'recharts';

// ═══════════════════════════════════════════════════════════════════════════
// DDoS Tester — generates a "victim" origin app that stays healthy under a set
// RPS threshold and then simulates an origin under L7 DDoS distress (errors +
// rising latency) once traffic exceeds it. Also fires traffic to trigger it,
// so you can demo how F5 L7 DDoS detection/mitigation kicks in at low RPS.
// ═══════════════════════════════════════════════════════════════════════════

type Stack = 'php' | 'node' | 'python' | 'go';

interface GenConfig {
  threshold: number;         // sustained RPS above which the origin starts to degrade
  windowMs: number;          // sliding window used to measure the rate
  errorCode: number;         // error status mixed in while distressed (503/500/429…)
  normalLatencyMs: number;   // baseline latency when healthy
  distressLatencyMs: number; // max injected latency at full distress
  holdSec: number;           // how long distress persists after being tripped
  minErrorRatio: number;     // % of requests that 5xx the INSTANT it trips (floor)
  maxErrorRatio: number;     // % of requests that 5xx at full severity (rest stay 200)
  rampSec: number;           // seconds over which severity ramps floor→full once tripped
  port: number;              // listen port for the standalone servers
}

const STACKS: { id: Stack; label: string; file: string; hint: string }[] = [
  { id: 'php', label: 'PHP', file: 'index.php', hint: 'Drop into any LAMP / PHP-FPM host' },
  { id: 'node', label: 'Node.js', file: 'server.js', hint: 'Zero-dependency http server' },
  { id: 'python', label: 'Python', file: 'app.py', hint: 'Standard library only (Python 3)' },
  { id: 'go', label: 'Go', file: 'main.go', hint: 'Single binary, net/http' },
];

const ERROR_CODES = [503, 500, 429, 502, 504];

// ── Code generators ──────────────────────────────────────────────────────────
// Each returns a single self-contained file. All share the same behaviour:
//   rate ≤ threshold  → 200 OK, baseline latency  ("healthy")
//   rate > threshold  → enter distress for holdSec (sustained by hysteresis while
//                       traffic continues). The error rate starts at minErrorRatio
//                       the instant it trips and ramps to maxErrorRatio over rampSec
//                       (faster the harder it's hit); latency climbs alongside — a
//                       realistic MIX of 200s + 5xx, never 100%.
// This rising-error-rate + rising-latency curve is what F5 XC reads as "origin
// health degradation" (its RELT Error-Rate + Latency signals). A /healthz endpoint
// always returns a fast 200 so F5 XC active health-checks keep the origin "up"
// (degraded, not down). Signal headers (X-Origin-State / X-Origin-Rate /
// X-Origin-Severity / Retry-After) are decorative for XC — for your own narration.

function genPHP(c: GenConfig): string {
  return `<?php
// ============================================================================
// F5 XC L7 DDoS demo origin (generated). Host this as your demo app's page.
//
// F5 XC L7 DDoS auto-mitigation triggers on a DUAL condition:
//   (1) request rate exceeds the LB's configured RPS threshold, AND
//   (2) "origin health degradation" — rising errors + latency at the origin
//       (the Error-Rate & Latency inputs of F5 XC's RELT signal set).
// This origin reproduces signal (2): normal under ${c.threshold} req/s, then degrades
// GRADUALLY above it — latency climbs and a growing share of requests return
// HTTP ${c.errorCode} (a realistic mix of 200 + errors, capped at ${c.maxErrorRatio}%), so F5 XC
// sees rising error-rate + latency and, with the RPS surge, trips mitigation.
//   Run standalone:  php -S 0.0.0.0:${c.port} index.php
//   Or drop index.php onto any existing PHP host.
// ============================================================================
$THRESHOLD          = ${c.threshold};
$WINDOW_MS          = ${c.windowMs};
$ERROR_CODE         = ${c.errorCode};
$NORMAL_LATENCY_MS  = ${c.normalLatencyMs};
$DISTRESS_LATENCY_MS= ${c.distressLatencyMs};
$HOLD_SEC           = ${c.holdSec};
$MIN_ERROR_RATIO    = ${c.minErrorRatio};
$MAX_ERROR_RATIO    = ${c.maxErrorRatio};
$RAMP_SEC           = ${c.rampSec};
// Deploy with DISTRESS=on to FORCE distress regardless of request rate — a bulletproof
// demo when your client can't reliably push the origin above the threshold.
$FORCE_DISTRESS = in_array(strtolower((string)getenv('DISTRESS')), array('1','true','on','yes'), true);

// Dedicated health endpoint: always a fast 200, bypassing distress and NOT counted toward
// the rate. Point your F5 XC origin-pool health check here so the origin stays "up"
// (degraded, not down) while the main path is under distress.
$reqPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (in_array($reqPath, array('/healthz', '/health', '/livez', '/readyz'), true)) {
  header('Content-Type: text/plain');
  header('Access-Control-Allow-Origin: *');
  http_response_code(200);
  echo 'ok';
  exit;
}

$now = microtime(true) * 1000.0;
$stateFile = sys_get_temp_dir() . '/ddos_demo_state.json';
$fp = fopen($stateFile, 'c+');
flock($fp, LOCK_EX);
$raw = stream_get_contents($fp);
$state = json_decode($raw, true);
if (!is_array($state)) { $state = array('hits' => array(), 'distressUntil' => 0, 'distressStart' => 0); }
$cut = $now - $WINDOW_MS;
$state['hits'] = array_values(array_filter($state['hits'], function($t) use ($cut) { return $t >= $cut; }));
$state['hits'][] = $now;
$rate = count($state['hits']) * (1000.0 / $WINDOW_MS);
// Trip when rate reaches threshold; keep the episode alive while ANY meaningful traffic
// continues (hysteresis at 10% of threshold) so the slow responses that throttle the
// attacker don't end distress prematurely.
if ($rate >= $THRESHOLD || ($now < $state['distressUntil'] && $rate > $THRESHOLD * 0.1)) {
  if ($now >= $state['distressUntil']) { $state['distressStart'] = $now; } // fresh distress episode
  $state['distressUntil'] = $now + $HOLD_SEC * 1000;
}
$distressed = $FORCE_DISTRESS || ($now < $state['distressUntil']);
ftruncate($fp, 0); rewind($fp); fwrite($fp, json_encode($state));
flock($fp, LOCK_UN); fclose($fp);

header('X-Origin-Rate: ' . round($rate, 1));
header('X-Origin-Threshold: ' . $THRESHOLD);
header('Access-Control-Allow-Origin: *');
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate'); // never let a CDN cache this — every request must reach the origin
header('Pragma: no-cache');

if ($distressed) {
  // Severity ramps 0->1 over RAMP_SEC by time since the episode began (harder hit ramps
  // faster via load) and reaches full regardless of the current rate.
  $ramp = max(0.0, min(1.0, ($now - $state['distressStart']) / ($RAMP_SEC * 1000)));
  $load = max(0.0, min(1.0, $rate / max(1, $THRESHOLD) - 1));
  $severity = max(0.0, min(1.0, $ramp * (1 + $load)));
  $latency = $NORMAL_LATENCY_MS + ($DISTRESS_LATENCY_MS - $NORMAL_LATENCY_MS) * $severity;
  usleep((int)($latency * 1000));
  // Error rate starts at MIN_ERROR_RATIO the instant we trip and climbs to MAX_ERROR_RATIO.
  $errorProb = ($MIN_ERROR_RATIO + ($MAX_ERROR_RATIO - $MIN_ERROR_RATIO) * $severity) / 100.0;
  $pct = round($errorProb * 100);
  header('X-Origin-State: distressed');
  header('X-Origin-Severity: ' . round($severity * 100));
  if ((mt_rand() / mt_getrandmax()) < $errorProb) {
    $retry = max(1, (int)ceil(($state['distressUntil'] - $now) / 1000));
    header('Retry-After: ' . $retry);
    http_response_code($ERROR_CODE);
    echo page('UNDER DISTRESS', '#ef4444', $rate, $THRESHOLD, 'Origin overwhelmed — HTTP ' . $ERROR_CODE . '. ~' . $pct . '% of requests failing.');
    exit;
  }
  echo page('DEGRADED', '#f59e0b', $rate, $THRESHOLD, 'Elevated latency; errors climbing (~' . $pct . '% failing).');
  exit;
}
usleep((int)($NORMAL_LATENCY_MS * 1000));
header('X-Origin-State: healthy');
echo page('HEALTHY', '#22c55e', $rate, $THRESHOLD, 'Serving normally under the threshold.');

function page($state, $color, $rate, $th, $msg) {
  return "<!doctype html><html><head><meta charset='utf-8'><title>Demo Origin</title></head>"
    . "<body style='font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;text-align:center;padding:64px'>"
    . "<h1 style='color:$color;font-size:34px;margin:0'>&#9679; $state</h1>"
    . "<p style='font-size:18px'>Request rate: <b>" . round($rate, 1) . " req/s</b> &nbsp;/&nbsp; threshold <b>$th req/s</b></p>"
    . "<p style='color:#94a3b8'>$msg</p>"
    . "<p style='color:#475569;font-size:12px;margin-top:40px'>F5 L7 DDoS demo origin</p>"
    . "</body></html>";
}
`;
}

function genNode(c: GenConfig): string {
  return `// ============================================================================
// F5 XC L7 DDoS demo origin (generated) — Node.js, zero dependencies.
//
// F5 XC L7 DDoS auto-mitigation triggers on a DUAL condition:
//   (1) request rate exceeds the LB's configured RPS threshold, AND
//   (2) "origin health degradation" — rising errors + latency at the origin
//       (the Error-Rate & Latency inputs of F5 XC's RELT signal set).
// This origin reproduces signal (2): normal under ${c.threshold} req/s, then degrades
// GRADUALLY — latency climbs and a growing share of requests return HTTP ${c.errorCode}
// (a mix of 200 + errors, capped at ${c.maxErrorRatio}%), so F5 XC sees rising error-rate + latency.
//   Run:  node server.js      (listens on $PORT or ${c.port})
// ============================================================================
const http = require('http');

const THRESHOLD = ${c.threshold};
const WINDOW_MS = ${c.windowMs};
const ERROR_CODE = ${c.errorCode};
const NORMAL_LATENCY_MS = ${c.normalLatencyMs};
const DISTRESS_LATENCY_MS = ${c.distressLatencyMs};
const HOLD_SEC = ${c.holdSec};
const MIN_ERROR_RATIO = ${c.minErrorRatio};
const MAX_ERROR_RATIO = ${c.maxErrorRatio};
const RAMP_SEC = ${c.rampSec};
const PORT = process.env.PORT || ${c.port};
// Deploy with DISTRESS=on to FORCE distress regardless of request rate — a bulletproof
// demo when your client can't reliably push the origin above the threshold.
const FORCE_DISTRESS = /^(1|true|on|yes)$/i.test(process.env.DISTRESS || '');

let hits = [];
let distressUntil = 0;
let distressStart = 0;
const clamp01 = (x) => Math.max(0, Math.min(1, x));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function page(state, color, rate, msg) {
  return "<!doctype html><html><head><meta charset='utf-8'><title>Demo Origin</title></head>" +
    "<body style='font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;text-align:center;padding:64px'>" +
    "<h1 style='color:" + color + ";font-size:34px;margin:0'>&#9679; " + state + "</h1>" +
    "<p style='font-size:18px'>Request rate: <b>" + rate.toFixed(1) + " req/s</b> &nbsp;/&nbsp; threshold <b>" + THRESHOLD + " req/s</b></p>" +
    "<p style='color:#94a3b8'>" + msg + "</p>" +
    "<p style='color:#475569;font-size:12px;margin-top:40px'>F5 L7 DDoS demo origin</p></body></html>";
}

const HEALTH_PATHS = ['/healthz', '/health', '/livez', '/readyz'];

const server = http.createServer(async (req, res) => {
  // Dedicated health endpoint: always a fast 200, bypassing distress and NOT counted
  // toward the rate. Point your F5 XC origin-pool health check here so the origin stays
  // "up" (degraded, not down) while the main path is under distress.
  const path = (req.url || '/').split('?')[0];
  if (HEALTH_PATHS.includes(path)) {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.statusCode = 200;
    res.end('ok');
    return;
  }
  const now = Date.now();
  const cut = now - WINDOW_MS;
  hits = hits.filter((t) => t >= cut);
  hits.push(now);
  const rate = hits.length * (1000 / WINDOW_MS);
  // Trip when rate reaches threshold; keep the episode alive while ANY meaningful traffic
  // continues (hysteresis at 10% of threshold) so the slow responses that throttle the
  // attacker don't end distress prematurely.
  if (rate >= THRESHOLD || (now < distressUntil && rate > THRESHOLD * 0.1)) {
    if (now >= distressUntil) distressStart = now; // start of a fresh distress episode
    distressUntil = now + HOLD_SEC * 1000;
  }
  const distressed = FORCE_DISTRESS || now < distressUntil;

  res.setHeader('X-Origin-Rate', rate.toFixed(1));
  res.setHeader('X-Origin-Threshold', String(THRESHOLD));
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate'); // never let a CDN cache this — every request must reach the origin
  res.setHeader('Pragma', 'no-cache');

  if (distressed) {
    // Severity ramps 0->1 over RAMP_SEC by time since the episode began (a harder hit
    // ramps faster via load) and reaches full regardless of the current rate.
    const ramp = clamp01((now - distressStart) / (RAMP_SEC * 1000));
    const load = clamp01(rate / Math.max(1, THRESHOLD) - 1);
    const severity = clamp01(ramp * (1 + load));
    const latency = NORMAL_LATENCY_MS + (DISTRESS_LATENCY_MS - NORMAL_LATENCY_MS) * severity;
    await sleep(latency);
    // Error rate starts at MIN_ERROR_RATIO the instant we trip and climbs to
    // MAX_ERROR_RATIO — so 5xx appear immediately, not only after a long ramp.
    const errorProb = (MIN_ERROR_RATIO + (MAX_ERROR_RATIO - MIN_ERROR_RATIO) * severity) / 100;
    const pct = Math.round(errorProb * 100);
    res.setHeader('X-Origin-State', 'distressed');
    res.setHeader('X-Origin-Severity', String(Math.round(severity * 100)));
    if (Math.random() < errorProb) {
      const retry = Math.max(1, Math.ceil((distressUntil - now) / 1000));
      res.setHeader('Retry-After', String(retry));
      res.statusCode = ERROR_CODE;
      res.end(page('UNDER DISTRESS', '#ef4444', rate, 'Origin overwhelmed — HTTP ' + ERROR_CODE + '. ~' + pct + '% of requests failing.'));
      return;
    }
    res.statusCode = 200;
    res.end(page('DEGRADED', '#f59e0b', rate, 'Elevated latency; errors climbing (~' + pct + '% failing).'));
    return;
  }
  await sleep(NORMAL_LATENCY_MS);
  res.setHeader('X-Origin-State', 'healthy');
  res.statusCode = 200;
  res.end(page('HEALTHY', '#22c55e', rate, 'Serving normally under the threshold.'));
});

server.listen(PORT, () => console.log('DDoS demo origin listening on :' + PORT + ' (threshold ' + THRESHOLD + ' req/s)'));
`;
}

function genPython(c: GenConfig): string {
  return `# ============================================================================
# F5 XC L7 DDoS demo origin (generated) — Python 3, standard library only.
#
# F5 XC L7 DDoS auto-mitigation triggers on a DUAL condition:
#   (1) request rate exceeds the LB's configured RPS threshold, AND
#   (2) "origin health degradation" — rising errors + latency at the origin
#       (the Error-Rate & Latency inputs of F5 XC's RELT signal set).
# This origin reproduces signal (2): normal under ${c.threshold} req/s, then degrades
# GRADUALLY — latency climbs and a growing share of requests return HTTP ${c.errorCode}
# (a mix of 200 + errors, capped at ${c.maxErrorRatio}%), so F5 XC sees rising error-rate + latency.
#   Run:  python3 app.py       (listens on $PORT or ${c.port})
# ============================================================================
import os, time, random, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

THRESHOLD = ${c.threshold}
WINDOW_MS = ${c.windowMs}
ERROR_CODE = ${c.errorCode}
NORMAL_LATENCY_MS = ${c.normalLatencyMs}
DISTRESS_LATENCY_MS = ${c.distressLatencyMs}
HOLD_SEC = ${c.holdSec}
MIN_ERROR_RATIO = ${c.minErrorRatio}
MAX_ERROR_RATIO = ${c.maxErrorRatio}
RAMP_SEC = ${c.rampSec}
PORT = int(os.environ.get('PORT', '${c.port}'))
# Deploy with DISTRESS=on to FORCE distress regardless of request rate — a bulletproof
# demo when your client can't reliably push the origin above the threshold.
FORCE_DISTRESS = os.environ.get('DISTRESS', '').lower() in ('1', 'true', 'on', 'yes')

_lock = threading.Lock()
_hits = []
_distress_until = 0.0
_distress_start = 0.0

def _clamp01(x):
    return max(0.0, min(1.0, x))

def _measure():
    global _hits, _distress_until, _distress_start
    now = time.time() * 1000.0
    with _lock:
        cut = now - WINDOW_MS
        _hits = [t for t in _hits if t >= cut]
        _hits.append(now)
        rate = len(_hits) * (1000.0 / WINDOW_MS)
        # Trip when rate reaches threshold; keep the episode alive while ANY meaningful traffic
        # continues (hysteresis at 10% of threshold) so the slow responses that throttle the
        # attacker don't end distress prematurely.
        if rate >= THRESHOLD or (now < _distress_until and rate > THRESHOLD * 0.1):
            if now >= _distress_until:
                _distress_start = now  # fresh distress episode
            _distress_until = now + HOLD_SEC * 1000
        distressed = FORCE_DISTRESS or now < _distress_until
        elapsed = now - _distress_start
        retry = max(1, int((_distress_until - now) / 1000) + 1)
    return now, rate, distressed, retry, elapsed

def _page(state, color, rate, msg):
    return ("<!doctype html><html><head><meta charset='utf-8'><title>Demo Origin</title></head>"
        "<body style='font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;text-align:center;padding:64px'>"
        "<h1 style='color:" + color + ";font-size:34px;margin:0'>&#9679; " + state + "</h1>"
        "<p style='font-size:18px'>Request rate: <b>" + ("%.1f" % rate) + " req/s</b> &nbsp;/&nbsp; threshold <b>" + str(THRESHOLD) + " req/s</b></p>"
        "<p style='color:#94a3b8'>" + msg + "</p>"
        "<p style='color:#475569;font-size:12px;margin-top:40px'>F5 L7 DDoS demo origin</p></body></html>")

HEALTH_PATHS = ('/healthz', '/health', '/livez', '/readyz')

class Handler(BaseHTTPRequestHandler):
    def _serve(self):
        # Dedicated health endpoint: always a fast 200, bypassing distress and NOT counted
        # toward the rate. Point your F5 XC origin-pool health check here so the origin stays
        # "up" (degraded, not down) while the main path is under distress.
        if self.path.split('?')[0] in HEALTH_PATHS:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers(); self.wfile.write(b'ok'); return
        now, rate, distressed, retry, elapsed = _measure()
        if distressed:
            # Severity ramps 0->1 over RAMP_SEC by time since the episode began (harder hit
            # ramps faster via load) and reaches full regardless of the current rate.
            ramp = _clamp01(elapsed / (RAMP_SEC * 1000.0))
            load = _clamp01(rate / max(1, THRESHOLD) - 1)
            severity = _clamp01(ramp * (1 + load))
            latency = NORMAL_LATENCY_MS + (DISTRESS_LATENCY_MS - NORMAL_LATENCY_MS) * severity
            time.sleep(latency / 1000.0)
            # Error rate starts at MIN_ERROR_RATIO the instant we trip and climbs to MAX_ERROR_RATIO.
            error_prob = (MIN_ERROR_RATIO + (MAX_ERROR_RATIO - MIN_ERROR_RATIO) * severity) / 100.0
            pct = round(error_prob * 100)
            if random.random() < error_prob:
                body = _page('UNDER DISTRESS', '#ef4444', rate, 'Origin overwhelmed — HTTP ' + str(ERROR_CODE) + '. ~' + str(pct) + '% of requests failing.').encode()
                self.send_response(ERROR_CODE)
                self.send_header('X-Origin-State', 'distressed')
                self.send_header('X-Origin-Severity', str(round(severity * 100)))
                self.send_header('Retry-After', str(retry))
                self._common(rate); self.end_headers(); self.wfile.write(body); return
            body = _page('DEGRADED', '#f59e0b', rate, 'Elevated latency; errors climbing (~' + str(pct) + '% failing).').encode()
            self.send_response(200); self.send_header('X-Origin-State', 'distressed')
            self.send_header('X-Origin-Severity', str(round(severity * 100)))
            self._common(rate); self.end_headers(); self.wfile.write(body); return
        time.sleep(NORMAL_LATENCY_MS / 1000.0)
        body = _page('HEALTHY', '#22c55e', rate, 'Serving normally under the threshold.').encode()
        self.send_response(200); self.send_header('X-Origin-State', 'healthy')
        self._common(rate); self.end_headers(); self.wfile.write(body)

    def _common(self, rate):
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')  # never let a CDN cache this
        self.send_header('Pragma', 'no-cache')
        self.send_header('X-Origin-Rate', '%.1f' % rate)
        self.send_header('X-Origin-Threshold', str(THRESHOLD))

    do_GET = _serve
    do_POST = _serve
    def log_message(self, *args):
        pass

if __name__ == '__main__':
    print('DDoS demo origin listening on :' + str(PORT) + ' (threshold ' + str(THRESHOLD) + ' req/s)')
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
`;
}

function genGo(c: GenConfig): string {
  return `// ============================================================================
// F5 XC L7 DDoS demo origin (generated) — Go, net/http.
//
// F5 XC L7 DDoS auto-mitigation triggers on a DUAL condition:
//   (1) request rate exceeds the LB's configured RPS threshold, AND
//   (2) "origin health degradation" — rising errors + latency at the origin
//       (the Error-Rate & Latency inputs of F5 XC's RELT signal set).
// This origin reproduces signal (2): normal under ${c.threshold} req/s, then degrades
// GRADUALLY — latency climbs and a growing share of requests return HTTP ${c.errorCode}
// (a mix of 200 + errors, capped at ${c.maxErrorRatio}%), so F5 XC sees rising error-rate + latency.
//   Run:  go run main.go      (listens on $PORT or ${c.port})
// ============================================================================
package main

import (
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	threshold         = ${c.threshold}
	windowMs          = ${c.windowMs}
	errorCode         = ${c.errorCode}
	normalLatencyMs   = ${c.normalLatencyMs}
	distressLatencyMs = ${c.distressLatencyMs}
	holdSec           = ${c.holdSec}
	minErrorRatio     = ${c.minErrorRatio}
	maxErrorRatio     = ${c.maxErrorRatio}
	rampSec           = ${c.rampSec}
)

var (
	mu            sync.Mutex
	hits          []int64
	distressUntil int64
	distressStart int64
)

// Deploy with DISTRESS=on to FORCE distress regardless of request rate — a bulletproof
// demo when your client can't reliably push the origin above the threshold.
func envOn(v string) bool { return v == "1" || v == "true" || v == "on" || v == "yes" }

var forceDistress = envOn(os.Getenv("DISTRESS"))

func clamp01(x float64) float64 { return math.Max(0, math.Min(1, x)) }

func measure() (int64, float64, bool, int64, int) {
	now := time.Now().UnixMilli()
	mu.Lock()
	defer mu.Unlock()
	cut := now - windowMs
	keep := hits[:0]
	for _, t := range hits {
		if t >= cut {
			keep = append(keep, t)
		}
	}
	hits = append(keep, now)
	rate := float64(len(hits)) * (1000.0 / windowMs)
	// Trip when rate reaches threshold; keep the episode alive while ANY meaningful traffic
	// continues (hysteresis at 10% of threshold) so the slow responses that throttle the
	// attacker don't end distress prematurely.
	if rate >= threshold || (now < distressUntil && rate > threshold*0.1) {
		if now >= distressUntil {
			distressStart = now // fresh distress episode
		}
		distressUntil = now + holdSec*1000
	}
	retry := int((distressUntil-now)/1000) + 1
	if retry < 1 {
		retry = 1
	}
	return now, rate, now < distressUntil, now - distressStart, retry
}

func page(state, color string, rate float64, msg string) string {
	return "<!doctype html><html><head><meta charset='utf-8'><title>Demo Origin</title></head>" +
		"<body style='font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;text-align:center;padding:64px'>" +
		"<h1 style='color:" + color + ";font-size:34px;margin:0'>&#9679; " + state + "</h1>" +
		"<p style='font-size:18px'>Request rate: <b>" + strconv.FormatFloat(rate, 'f', 1, 64) + " req/s</b> &nbsp;/&nbsp; threshold <b>" + strconv.Itoa(threshold) + " req/s</b></p>" +
		"<p style='color:#94a3b8'>" + msg + "</p>" +
		"<p style='color:#475569;font-size:12px;margin-top:40px'>F5 L7 DDoS demo origin</p></body></html>"
}

func isHealthPath(p string) bool {
	return p == "/healthz" || p == "/health" || p == "/livez" || p == "/readyz"
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Dedicated health endpoint: always a fast 200, bypassing distress and NOT counted
	// toward the rate. Point your F5 XC origin-pool health check here so the origin stays
	// "up" (degraded, not down) while the main path is under distress.
	if isHealthPath(r.URL.Path) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, "ok")
		return
	}
	now, rate, distressed, elapsed, retry := measure()
	w.Header().Set("X-Origin-Rate", strconv.FormatFloat(rate, 'f', 1, 64))
	w.Header().Set("X-Origin-Threshold", strconv.Itoa(threshold))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate") // never let a CDN cache this
	w.Header().Set("Pragma", "no-cache")
	_ = now
	distressed = distressed || forceDistress

	if distressed {
		// Severity ramps 0->1 over rampSec by time since the episode began (harder hit ramps
		// faster via load) and reaches full regardless of the current rate.
		ramp := clamp01(float64(elapsed) / (rampSec * 1000))
		load := clamp01(rate/float64(threshold) - 1)
		severity := clamp01(ramp * (1 + load))
		latency := normalLatencyMs + (distressLatencyMs-normalLatencyMs)*severity
		time.Sleep(time.Duration(latency) * time.Millisecond)
		// Error rate starts at minErrorRatio the instant we trip and climbs to maxErrorRatio.
		errorProb := (minErrorRatio + (maxErrorRatio-minErrorRatio)*severity) / 100.0
		pct := strconv.Itoa(int(errorProb*100 + 0.5))
		w.Header().Set("X-Origin-State", "distressed")
		w.Header().Set("X-Origin-Severity", strconv.Itoa(int(severity*100+0.5)))
		if rand.Float64() < errorProb {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			w.WriteHeader(errorCode)
			fmt.Fprint(w, page("UNDER DISTRESS", "#ef4444", rate, "Origin overwhelmed — HTTP "+strconv.Itoa(errorCode)+". ~"+pct+"% of requests failing."))
			return
		}
		fmt.Fprint(w, page("DEGRADED", "#f59e0b", rate, "Elevated latency; errors climbing (~"+pct+"% failing)."))
		return
	}
	time.Sleep(normalLatencyMs * time.Millisecond)
	w.Header().Set("X-Origin-State", "healthy")
	fmt.Fprint(w, page("HEALTHY", "#22c55e", rate, "Serving normally under the threshold."))
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "${c.port}"
	}
	http.HandleFunc("/", handler)
	fmt.Println("DDoS demo origin listening on :" + port + " (threshold " + strconv.Itoa(threshold) + " req/s)")
	http.ListenAndServe(":"+port, nil)
}
`;
}

function genCode(stack: Stack, c: GenConfig): string {
  switch (stack) {
    case 'php': return genPHP(c);
    case 'node': return genNode(c);
    case 'python': return genPython(c);
    case 'go': return genGo(c);
  }
}

const lowPortNote = (c: GenConfig) => c.port < 1024 ? ` (port ${c.port} needs sudo/root, or set PORT=8080)` : ` (override with PORT=8080)`;

function deployInstructions(stack: Stack, c: GenConfig): string[] {
  const poolStep = 'Point your F5 XC origin pool at this host; set the pool health-check path to /healthz so the origin stays "up" while degrading.';
  switch (stack) {
    case 'php': return [
      'Download index.php and copy it onto your demo origin (any PHP host / web root).',
      `Or run standalone:  php -S 0.0.0.0:${c.port} index.php${lowPortNote(c)}.`,
      `Guaranteed demo (5xx regardless of traffic):  DISTRESS=on php -S 0.0.0.0:${c.port} index.php`,
      poolStep,
    ];
    case 'node': return [
      'Download server.js onto a host with Node.js installed (no npm install needed).',
      `Run:  node server.js${lowPortNote(c)}.`,
      'Guaranteed demo (5xx regardless of traffic):  DISTRESS=on node server.js',
      poolStep,
    ];
    case 'python': return [
      'Download app.py onto a host with Python 3 (standard library only — no pip install).',
      `Run:  python3 app.py${lowPortNote(c)}.`,
      'Guaranteed demo (5xx regardless of traffic):  DISTRESS=on python3 app.py',
      poolStep,
    ];
    case 'go': return [
      'Download main.go onto a host with Go installed.',
      `Run:  go run main.go${lowPortNote(c)}.`,
      'Guaranteed demo (5xx regardless of traffic):  DISTRESS=on go run main.go',
      poolStep,
    ];
  }
}

// ── Attack runner types ──────────────────────────────────────────────────────

interface ReqResult { t: number; status: number; ms: number; err?: string }

interface CumTotals { sent: number; done: number; ok: number; s5xx: number; c4xx: number; net: number; dist: Record<string, number> }
const EMPTY_TOTALS: CumTotals = { sent: 0, done: 0, ok: 0, s5xx: 0, c4xx: 0, net: 0, dist: {} };

// ═══════════════════════════════════════════════════════════════════════════
// COMPONENT
// ═══════════════════════════════════════════════════════════════════════════

export function DdosTester() {
  const navigate = useNavigate();
  const [tab, setTab] = useState<'generate' | 'attack'>('generate');

  // ── Generator state ──
  const [stack, setStack] = useState<Stack>('php');
  const [cfg, setCfg] = useState<GenConfig>({
    threshold: 5, windowMs: 1000, errorCode: 503,
    normalLatencyMs: 20, distressLatencyMs: 1000, holdSec: 30,
    minErrorRatio: 40, maxErrorRatio: 90, rampSec: 3, port: 443,
  });
  const [copied, setCopied] = useState(false);

  const code = useMemo(() => genCode(stack, cfg), [stack, cfg]);
  const activeStack = STACKS.find(s => s.id === stack)!;

  const download = () => {
    const blob = new Blob([code], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = activeStack.file;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
  };
  const copy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true); setTimeout(() => setCopied(false), 1500);
  };
  const setNum = (k: keyof GenConfig, v: number) => setCfg(c => ({ ...c, [k]: v }));

  // ── Attack runner state ──
  const [url, setUrl] = useState('');
  const [rps, setRps] = useState(15);
  const [cacheBust, setCacheBust] = useState(true);
  const [runMode, setRunMode] = useState<'sustained' | 'fixed'>('sustained');
  const [duration, setDuration] = useState(60);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<ReqResult[]>([]);
  const [elapsed, setElapsed] = useState(0);
  const [totals, setTotals] = useState<CumTotals>({ ...EMPTY_TOTALS });
  const [firstTrigger, setFirstTrigger] = useState<{ ms: number; reqs: number; code: number } | null>(null);

  const abortRef = useRef(false);
  const resultsRef = useRef<ReqResult[]>([]);
  const inFlightRef = useRef(0);
  const sentRef = useRef(0);
  const startRef = useRef(0);
  const cumRef = useRef({ done: 0, ok: 0, s5xx: 0, c4xx: 0, net: 0, dist: new Map<string, number>() });
  const firstTriggerRef = useRef<{ ms: number; reqs: number; code: number } | null>(null);
  const bustRef = useRef(0);
  const dispatchRef = useRef<ReturnType<typeof setInterval>>();
  const uiRef = useRef<ReturnType<typeof setInterval>>();

  useEffect(() => () => { abortRef.current = true; clearInterval(dispatchRef.current); clearInterval(uiRef.current); }, []);

  const fullUrl = url.trim();
  const urlValid = useMemo(() => { if (!fullUrl) return false; try { new URL(fullUrl); return true; } catch { return false; } }, [fullUrl]);

  const startAttack = useCallback(() => {
    if (!urlValid) return;
    resultsRef.current = []; sentRef.current = 0; inFlightRef.current = 0;
    cumRef.current = { done: 0, ok: 0, s5xx: 0, c4xx: 0, net: 0, dist: new Map() };
    firstTriggerRef.current = null;
    abortRef.current = false; startRef.current = Date.now();
    setResults([]); setElapsed(0); setTotals({ ...EMPTY_TOTALS }); setFirstTrigger(null); setRunning(true);

    const start = Date.now();
    const durMs = runMode === 'sustained' ? Infinity : duration * 1000;

    const record = (res: ReqResult) => {
      const arr = resultsRef.current;
      arr.push(res);
      if (arr.length > 8000) arr.splice(0, arr.length - 8000); // keep memory bounded on long sustained runs
      const c = cumRef.current;
      c.done++;
      if (res.status >= 200 && res.status < 400) c.ok++;
      else if (res.status >= 500) c.s5xx++;
      else if (res.status >= 400) c.c4xx++;
      else if (res.status === 0) c.net++;
      const key = res.status === 0 ? 'ERR' : String(res.status);
      c.dist.set(key, (c.dist.get(key) || 0) + 1);
      // First blocking/distress response = the trigger: 429 (F5 rate-limit), 403 (F5
      // block/challenge), or 5xx (origin distress feeding L7 DDoS).
      if (!firstTriggerRef.current && (res.status >= 500 || res.status === 429 || res.status === 403)) {
        firstTriggerRef.current = { ms: res.t, reqs: sentRef.current, code: res.status };
      }
    };

    const sendOne = async () => {
      inFlightRef.current++;
      try {
        // Cache-bust: a unique query param per request forces a CDN/cache MISS so every
        // request reaches the origin (otherwise a cached 200 is served and the origin
        // never sees the load → never distresses).
        let target = fullUrl;
        if (cacheBust) target += (fullUrl.includes('?') ? '&' : '?') + '_ddos=' + (bustRef.current++);
        const resp = await fetch('/api/load-test', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: target, method: 'GET', headers: { 'Cache-Control': 'no-cache', 'Pragma': 'no-cache' } }),
        });
        const d = await resp.json();
        record({ t: Date.now() - start, status: d.statusCode || 0, ms: d.responseTimeMs ?? 0, err: d.error });
      } catch (e: any) {
        record({ t: Date.now() - start, status: 0, ms: 0, err: e.message || 'proxy error' });
      } finally { inFlightRef.current--; }
    };

    const snapshot = () => {
      const c = cumRef.current;
      setResults([...resultsRef.current]);
      setElapsed(Date.now() - start);
      setTotals({ sent: sentRef.current, done: c.done, ok: c.ok, s5xx: c.s5xx, c4xx: c.c4xx, net: c.net, dist: Object.fromEntries(c.dist) });
      setFirstTrigger(firstTriggerRef.current);
    };

    // Cap concurrent in-flight proxy requests. A slow (distressed) origin makes each
    // request take ~1s, so an uncapped open-loop sender piles up fetches until the
    // browser dies with net::ERR_INSUFFICIENT_RESOURCES. With the cap, achieved RPS is
    // bounded by (MAX_INFLIGHT / origin latency) — honest, and enough to trip + hold distress.
    const MAX_INFLIGHT = 60;
    dispatchRef.current = setInterval(() => {
      const el = Date.now() - start;
      if (abortRef.current || el >= durMs) {
        clearInterval(dispatchRef.current);
        const fin = setInterval(() => {
          snapshot();
          if (inFlightRef.current === 0) { clearInterval(fin); clearInterval(uiRef.current); setRunning(false); }
        }, 100);
        return;
      }
      const expected = Math.floor(el * rps / 1000);
      const toSend = Math.min(expected - sentRef.current, MAX_INFLIGHT);
      for (let i = 0; i < toSend && inFlightRef.current < MAX_INFLIGHT; i++) { sentRef.current++; sendOne(); }
    }, 50);

    uiRef.current = setInterval(snapshot, 200);
  }, [fullUrl, urlValid, rps, cacheBust, runMode, duration]);

  const stopAttack = useCallback(() => {
    abortRef.current = true; clearInterval(dispatchRef.current); clearInterval(uiRef.current);
    const c = cumRef.current;
    setRunning(false); setResults([...resultsRef.current]); setElapsed(Date.now() - startRef.current);
    setTotals({ sent: sentRef.current, done: c.done, ok: c.ok, s5xx: c.s5xx, c4xx: c.c4xx, net: c.net, dist: Object.fromEntries(c.dist) });
    setFirstTrigger(firstTriggerRef.current);
  }, []);

  // ── Attack stats — lifetime totals from cumulative counters, live latency /
  // RPS / distress from the retained recent window.
  const stats = useMemo(() => {
    if (totals.done === 0 && results.length === 0) return null;
    const times = results.filter(r => r.ms > 0).map(r => r.ms).sort((a, b) => a - b);
    const avg = times.length ? times.reduce((s, t) => s + t, 0) / times.length : 0;
    const p95 = times.length ? times[Math.floor(times.length * 0.95)] : 0;
    const recent = results.filter(r => r.t > elapsed - 2000);
    const recentErr = recent.filter(r => r.status >= 500 || r.status === 0).length;
    const recentMit = recent.filter(r => r.status === 429 || r.status === 403).length;
    const distressed = recent.length >= 3 && recentErr / recent.length >= 0.2;   // origin 5xx
    const mitigated = recent.length >= 3 && recentMit / recent.length >= 0.2;     // F5 rate-limit / block
    const win = Math.min(2, elapsed / 1000);
    const curRps = win > 0 ? recent.length / win : 0;
    const blocked = (totals.dist['429'] || 0) + (totals.dist['403'] || 0);
    return {
      total: totals.sent, done: totals.done, ok: totals.ok, serverErr: totals.s5xx,
      clientErr: totals.c4xx, netErr: totals.net, blocked, avg, p95, distressed, mitigated, curRps, dist: totals.dist,
    };
  }, [totals, results, elapsed]);

  const chartData = useMemo(() => {
    if (results.length === 0) return [];
    const buckets = new Map<number, ReqResult[]>();
    for (const r of results) { const s = Math.floor(r.t / 1000); if (!buckets.has(s)) buckets.set(s, []); buckets.get(s)!.push(r); }
    return [...buckets.entries()].sort(([a], [b]) => a - b).map(([s, rs]) => {
      const errs = rs.filter(r => r.status >= 500 || r.status === 0).length;
      const times = rs.filter(r => r.ms > 0).map(r => r.ms);
      return {
        time: s + 's', rps: rs.length,
        errPct: rs.length ? Math.round((errs / rs.length) * 100) : 0,
        latency: times.length ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : 0,
      };
    });
  }, [results]);

  const statusColor = (code: number) => code === 0 ? 'text-slate-400' : code < 400 ? 'text-emerald-400' : code < 500 ? 'text-amber-400' : 'text-red-400';

  const NI = 'px-2 py-1.5 bg-slate-700 border border-slate-600 rounded text-center font-mono text-sm w-24 [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none';

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
      {/* Header */}
      <div className="border-b border-slate-700/50 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center gap-4">
          <button onClick={() => navigate('/')} className="p-2 hover:bg-slate-800 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-slate-400" />
          </button>
          <div className="w-10 h-10 rounded-xl bg-red-500/10 flex items-center justify-center">
            <ShieldAlert className="w-5 h-5 text-red-400" />
          </div>
          <div className="flex-1">
            <h1 className="text-xl font-bold">DDoS Tester</h1>
            <p className="text-sm text-slate-400">Generate a self-degrading origin, then drive traffic to demo F5 XC rate-limiting &amp; L7 DDoS mitigation at low RPS</p>
          </div>
        </div>
        {/* Tabs */}
        <div className="max-w-7xl mx-auto px-6 flex gap-1">
          {([['generate', 'Generate Origin App', Server], ['attack', 'Run Attack', Rocket]] as const).map(([id, label, Icon]) => (
            <button key={id} onClick={() => setTab(id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${tab === id ? 'border-red-500 text-red-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>
              <Icon className="w-4 h-4" /> {label}
            </button>
          ))}
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {tab === 'generate' && (
          <>
            {/* The honest reality + the two recipes (grounded in F5 XC docs) */}
            <div className="bg-slate-800/50 rounded-xl border border-amber-500/30 p-5">
              <h2 className="text-sm font-semibold text-amber-300 mb-1 flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> How to actually trigger this in F5 XC — and why 5–10 RPS alone won't fire L7 DDoS</h2>
              <p className="text-xs text-slate-400 mb-3">Per F5's docs, L7 DDoS auto-mitigation fires only when <span className="text-red-300">both</span> the RPS threshold is exceeded <span className="text-red-300">and</span> origin health degrades — and F5's Alerts Reference lists L7-DDoS anomaly <span className="text-white">minimums of ~100 rps and ~50 errors/sec</span> (not user-configurable). So a few RPS against a healthy origin simply can't trip it. For a clean low-RPS demo, use Rate Limiting; to demo the DDoS feature itself, you need volume <span className="text-white">and</span> a degrading origin.</p>
              <div className="grid md:grid-cols-2 gap-4 text-xs text-slate-300 leading-relaxed">
                <div className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 p-3 space-y-1.5">
                  <p className="font-semibold text-emerald-300">✅ Recipe A — Rate Limiting (deterministic · low RPS · recommended)</p>
                  <p>Fires at the exact rate you set — no origin/ML/learning dependency. HTTP LB → <span className="font-mono">Common Security Controls → Rate Limiting → Custom</span>:</p>
                  <ul className="list-disc pl-4 space-y-0.5 text-slate-400">
                    <li><span className="text-white">Number of Requests = 5</span>, Per Period = 1 Second</li>
                    <li><span className="text-white">Burst Multiplier = 1</span> — effective limit is <span className="font-mono">requests × burst</span>, so a default &gt;1 is why "5" won't block at ~10.</li>
                    <li>User identifier = <span className="text-white">Client IP</span> (default) — this tool sends from one proxy IP, so all requests share one bucket and trip cleanly.</li>
                    <li>Mitigation Action = <span className="text-white">Block</span> + Duration → <span className="font-mono text-emerald-300">HTTP 429</span>.</li>
                  </ul>
                  <p className="text-slate-500">No special origin needed — point the Attack tab at your LB and send &gt;5 RPS. This tool flags the 429s as the trigger.</p>
                </div>
                <div className="rounded-lg border border-red-500/25 bg-red-500/5 p-3 space-y-1.5">
                  <p className="font-semibold text-red-300">⚠ Recipe B — L7 DDoS Auto-Mitigation (needs ~100+ RPS + degrading origin)</p>
                  <p>HTTP LB → <span className="font-mono">Security Configuration → Show Advanced Fields → DoS Protection</span>:</p>
                  <ul className="list-disc pl-4 space-y-0.5 text-slate-400">
                    <li><span className="text-white">DDoS Detection = Enable</span>, <span className="text-white">Auto Mitigation = Enable</span> (Detection on + Auto-Mit off = monitor only).</li>
                    <li><span className="text-white">RPS threshold</span> (default 10,000) → lower it (e.g. 50–100).</li>
                    <li>Mitigation Action = <span className="text-white">Block / JS / CAPTCHA</span>.</li>
                    <li>Origin pool → <span className="text-red-300">this generated origin</span>; point the pool <span className="text-white">health check at /healthz</span> so it stays "up" while degrading. Then sustain <span className="text-white">~100+ RPS</span> so error-rate (~50+/s) + latency cross the anomaly floor.</li>
                  </ul>
                  <p className="text-slate-500">Honest caveat: still ML/time-of-day-baseline gated, so timing-sensitive and less repeatable than Recipe A.</p>
                </div>
              </div>
              <p className="text-[10px] text-slate-500 mt-3 pt-3 border-t border-slate-700/50">Other XC levers: <span className="font-mono">Slow DDoS Mitigation</span> (Slowloris — Request-Headers / Total-Request timeouts), static <span className="font-mono">DDoS Mitigation Rules</span> (IP / ASN+Region+TLS-fingerprint), <span className="font-mono">Malicious User / UBA</span> (needs an App Type + App Settings label). Sources: F5 XC docs — DDoS Detection (RELT metrics; RPS default 10,000; RPS + origin-health gate), Alerts Reference (~100 rps / 50 erps L7-DDoS anomaly minimums), Configure Rate Limiting; DevCentral L7 DoS roundup. Exact origin-health thresholds are not published — this origin is a controllable stand-in.</p>
            </div>

            {/* Stack picker */}
            <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
              <h2 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2"><Terminal className="w-4 h-4" /> 1. Pick your origin's stack</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {STACKS.map(s => (
                  <button key={s.id} onClick={() => setStack(s.id)}
                    className={`p-4 rounded-lg border text-left transition-colors ${stack === s.id ? 'bg-red-500/15 border-red-500 text-red-200' : 'bg-slate-900/50 border-slate-700 text-slate-300 hover:border-slate-500'}`}>
                    <div className="font-bold">{s.label}</div>
                    <div className="text-[11px] text-slate-500 mt-0.5 font-mono">{s.file}</div>
                    <div className="text-[11px] text-slate-500 mt-1">{s.hint}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Distress config */}
            <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
              <h2 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2"><Gauge className="w-4 h-4" /> 2. Tune the distress behaviour</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <Field label="Trigger threshold" hint="RPS above which origin trips">
                  <div className="flex items-center gap-1"><input type="number" min={1} value={cfg.threshold} onChange={e => setNum('threshold', Math.max(1, +e.target.value || 1))} className={NI} /><span className="text-slate-500">RPS</span></div>
                </Field>
                <Field label="Error status" hint="Mixed in while distressed">
                  <select value={cfg.errorCode} onChange={e => setNum('errorCode', +e.target.value)} className="px-2 py-1.5 bg-slate-700 border border-slate-600 rounded text-sm font-mono w-24">
                    {ERROR_CODES.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </Field>
                <Field label="Min error %" hint="5xx share the instant it trips (floor)">
                  <div className="flex items-center gap-1"><input type="number" min={0} max={100} value={cfg.minErrorRatio} onChange={e => setNum('minErrorRatio', Math.max(0, Math.min(100, +e.target.value || 0)))} className={NI} /><span className="text-slate-500">%</span></div>
                </Field>
                <Field label="Max error %" hint="5xx share at full severity (rest stay 200)">
                  <div className="flex items-center gap-1"><input type="number" min={0} max={100} value={cfg.maxErrorRatio} onChange={e => setNum('maxErrorRatio', Math.max(0, Math.min(100, +e.target.value || 0)))} className={NI} /><span className="text-slate-500">%</span></div>
                </Field>
                <Field label="Ramp-up" hint="Time to grow from min% → max%">
                  <div className="flex items-center gap-1"><input type="number" min={0} value={cfg.rampSec} onChange={e => setNum('rampSec', Math.max(0, +e.target.value || 0))} className={NI} /><span className="text-slate-500">sec</span></div>
                </Field>
                <Field label="Distress hold" hint="How long distress persists">
                  <div className="flex items-center gap-1"><input type="number" min={1} value={cfg.holdSec} onChange={e => setNum('holdSec', Math.max(1, +e.target.value || 1))} className={NI} /><span className="text-slate-500">sec</span></div>
                </Field>
                <Field label="Distress latency" hint="Max injected latency at full severity">
                  <div className="flex items-center gap-1"><input type="number" min={0} value={cfg.distressLatencyMs} onChange={e => setNum('distressLatencyMs', Math.max(0, +e.target.value || 0))} className={NI} /><span className="text-slate-500">ms</span></div>
                </Field>
                <Field label="Listen port" hint="Standalone servers only">
                  <input type="number" min={1} value={cfg.port} onChange={e => setNum('port', Math.max(1, +e.target.value || 8080))} className={NI} />
                </Field>
              </div>
              <div className="mt-4 rounded-lg border border-slate-700/60 bg-slate-900/40 p-3 text-xs text-slate-300 space-y-1.5">
                <p className="font-semibold text-slate-200 flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5 text-amber-400" /> When does it return 5xx? (and what to do if it doesn't)</p>
                <p>As soon as the origin actually <span className="text-white">receives ≥ {cfg.threshold} req/s</span> (measured over a {cfg.windowMs / 1000}s window) it trips: <span className="text-white">~{cfg.minErrorRatio}% of requests return {cfg.errorCode}</span> immediately, climbing to <span className="text-white">~{cfg.maxErrorRatio}%</span> over ~{cfg.rampSec}s while latency rises to {cfg.distressLatencyMs}ms, held {cfg.holdSec}s.</p>
                <p><span className="text-amber-300">All 200, no 5xx?</span> The rate is counted <span className="text-white">at the origin</span>, so traffic must actually reach it: <span className="text-white">(a) caching</span> — if your LB/CDN caches, a cached 200 is served and the origin never sees the load (the usual cause). Keep <span className="text-white">Cache-bust</span> ON, and disable caching on the LB. <span className="text-white">(b)</span> deliver ≥ {cfg.threshold} req/s — a browser tab / single <span className="font-mono">curl</span> is ~1 RPS; use the Attack tab or a real load tool. <span className="text-white">(c)</span> run <span className="text-white">one</span> origin instance — multiple workers/replicas each see only their share.</p>
                <p className="text-emerald-300">Guaranteed demo: deploy the origin with <span className="font-mono">DISTRESS=on</span> — it then degrades regardless of rate. <span className="font-mono text-emerald-400/80">/healthz</span> still returns 200 so the pool stays "up."</p>
              </div>
            </div>

            {/* Generated code + deploy */}
            <div className="grid lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 bg-slate-800/50 rounded-xl border border-slate-700/50 overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-700/50 bg-slate-900/50">
                  <span className="text-sm font-mono text-slate-300 flex items-center gap-2"><Server className="w-4 h-4 text-red-400" /> {activeStack.file}</span>
                  <div className="flex items-center gap-2">
                    <button onClick={copy} className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-slate-700 hover:bg-slate-600 rounded-md transition-colors">
                      {copied ? <><Check className="w-3.5 h-3.5 text-emerald-400" /> Copied</> : <><Copy className="w-3.5 h-3.5" /> Copy</>}
                    </button>
                    <button onClick={download} className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-red-600 hover:bg-red-500 rounded-md font-semibold transition-colors">
                      <Download className="w-3.5 h-3.5" /> Download
                    </button>
                  </div>
                </div>
                <pre className="p-4 text-[11px] leading-relaxed font-mono text-slate-300 overflow-auto max-h-[520px] custom-scrollbar">{code}</pre>
              </div>
              <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5 h-fit">
                <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2"><Rocket className="w-4 h-4 text-red-400" /> Deploy &amp; demo</h3>
                <ol className="space-y-3">
                  {deployInstructions(stack, cfg).map((step, i) => (
                    <li key={i} className="flex gap-2.5 text-xs text-slate-300">
                      <span className="shrink-0 w-5 h-5 rounded-full bg-red-500/15 text-red-300 flex items-center justify-center font-bold">{i + 1}</span>
                      <span className="pt-0.5 leading-relaxed">{step}</span>
                    </li>
                  ))}
                  <li className="flex gap-2.5 text-xs text-slate-300">
                    <span className="shrink-0 w-5 h-5 rounded-full bg-red-500/15 text-red-300 flex items-center justify-center font-bold">{deployInstructions(stack, cfg).length + 1}</span>
                    <span className="pt-0.5 leading-relaxed">Switch to the <button onClick={() => setTab('attack')} className="text-red-400 underline">Run Attack</button> tab and sustain traffic — a few RPS for Rate Limiting (429), or ~100+ RPS for L7 DDoS auto-mitigation.</span>
                  </li>
                </ol>
                <div className="mt-4 pt-4 border-t border-slate-700/50 text-[11px] text-slate-500 space-y-1">
                  <p className="font-semibold text-slate-400">Endpoints &amp; controls:</p>
                  <p className="font-mono text-emerald-400/80">/healthz → always 200 (point the pool health check here)</p>
                  <p className="font-mono text-amber-300/80">DISTRESS=on → force distress regardless of rate</p>
                  <p className="font-mono">X-Origin-State / X-Origin-Severity / Retry-After</p>
                </div>
              </div>
            </div>
          </>
        )}

        {tab === 'attack' && (
          <>
            {/* Step 1 — Target (full URL) */}
            <StepCard n={1} title="Target — where the test runs">
              <label className="block text-xs text-slate-400 mb-1">Full target URL <span className="text-slate-600">(your F5 XC LB endpoint fronting the origin)</span></label>
              <input value={url} onChange={e => setUrl(e.target.value)} disabled={running}
                placeholder="https://demo-app.example.com/path"
                className={`w-full px-3 py-2.5 bg-slate-700 border rounded-lg text-sm font-mono placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-red-500 ${url && !urlValid ? 'border-red-500' : 'border-slate-600'}`} />
              {url.trim() && !urlValid && (
                <p className="text-xs mt-2 text-red-400">Invalid URL — include the protocol (https://).</p>
              )}
            </StepCard>

            {/* Step 2 — Attack profile */}
            <StepCard n={2} title="Attack profile">
              <div className="flex flex-wrap items-center gap-6 text-sm">
                <div className="flex items-center gap-2">
                  <label className="text-slate-400">Sustained RPS:</label>
                  <input type="number" min={1} value={rps} onChange={e => setRps(Math.max(1, +e.target.value || 1))} disabled={running} className={NI} />
                </div>
                <div className="flex items-center gap-2">
                  <label className="text-slate-400">Run mode:</label>
                  <div className="flex bg-slate-700 rounded border border-slate-600 overflow-hidden">
                    {([['sustained', 'Sustained (until stopped)'], ['fixed', 'Fixed duration']] as const).map(([id, label]) => (
                      <button key={id} onClick={() => setRunMode(id)} disabled={running}
                        className={`px-3 py-1.5 text-xs font-medium transition-colors ${runMode === id ? 'bg-red-600 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-600'} disabled:opacity-50`}>
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
                {runMode === 'fixed' && (
                  <div className="flex items-center gap-2">
                    <label className="text-slate-400">Duration:</label>
                    <input type="number" min={1} value={duration} onChange={e => setDuration(Math.max(1, +e.target.value || 1))} disabled={running} className={NI} /><span className="text-slate-500">sec</span>
                  </div>
                )}
                <label className="flex items-center gap-2 cursor-pointer" title="Adds a unique query param per request so a CDN/cache can't serve a cached response — every request reaches the origin.">
                  <input type="checkbox" checked={cacheBust} onChange={e => setCacheBust(e.target.checked)} disabled={running} className="w-4 h-4 rounded border-slate-600 bg-slate-800 text-red-600" />
                  <span className="text-slate-400">Cache-bust</span>
                </label>
              </div>
              <p className="text-xs text-slate-500 mt-3 flex items-start gap-1.5">
                <Zap className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                <span>{runMode === 'sustained'
                  ? 'Fires a continuous, steady stream at the set RPS until you stop it.'
                  : 'Runs for a fixed window, then stops automatically.'}
                {' '}<span className="text-slate-400">Cache-bust</span> is essential if your LB/CDN caches — otherwise a cached 200 is served and the origin never sees the load (this is the usual cause of "all 200, no 5xx").</span>
              </p>
            </StepCard>

            {/* Step 3 — Run & observe */}
            <StepCard n={3} title="Run the sustained attack &amp; watch for the trigger">
              <div className="flex items-center gap-4 flex-wrap">
                {running ? (
                  <button onClick={stopAttack} className="px-6 py-2.5 bg-red-600 hover:bg-red-500 rounded-lg text-sm font-semibold flex items-center gap-2"><Square className="w-4 h-4" /> Stop attack</button>
                ) : (
                  <button onClick={startAttack} disabled={!urlValid} className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg text-sm font-semibold flex items-center gap-2"><Play className="w-4 h-4" /> Start attack</button>
                )}
                {(running || stats) && (
                  <div className="flex items-center gap-4 text-sm text-slate-400 font-mono">
                    <span>{running ? <span className="text-red-400">● running</span> : 'stopped'}</span>
                    <span>{(elapsed / 1000).toFixed(1)}s elapsed</span>
                    <span>{totals.sent} sent</span>
                    <span>{totals.done} completed</span>
                  </div>
                )}
              </div>
            </StepCard>

            {/* Live state — F5 mitigation (429/403) takes precedence over origin distress (5xx) */}
            {stats && (() => {
              const state = stats.mitigated ? 'mitigated' : stats.distressed ? 'distressed' : 'healthy';
              const skin = state === 'mitigated' ? 'bg-blue-500/10 border-blue-500/40'
                : state === 'distressed' ? 'bg-red-500/10 border-red-500/40'
                : 'bg-emerald-500/10 border-emerald-500/30';
              const Icon = state === 'mitigated' ? ShieldAlert : state === 'distressed' ? AlertTriangle : HeartPulse;
              const iconColor = state === 'mitigated' ? 'text-blue-400' : state === 'distressed' ? 'text-red-400' : 'text-emerald-400';
              const title = state === 'mitigated' ? 'F5 MITIGATION ACTIVE' : state === 'distressed' ? 'ORIGIN UNDER DISTRESS' : 'ORIGIN HEALTHY';
              const titleColor = state === 'mitigated' ? 'text-blue-300' : state === 'distressed' ? 'text-red-300' : 'text-emerald-300';
              const msg = state === 'mitigated'
                ? 'F5 XC is returning 429 / 403 — rate-limit or block is engaged. Traffic is being mitigated at the edge before it reaches the origin.'
                : state === 'distressed'
                  ? 'Origin is returning 5xx + high latency — "origin health degradation." At ~100+ RPS this feeds F5 XC L7 DDoS auto-mitigation.'
                  : `Serving normally at ~${stats.curRps.toFixed(1)} req/s. Push past the threshold (and add volume for L7 DDoS) to trip it.`;
              return (
                <div className={`rounded-xl border p-5 flex items-center gap-4 transition-colors ${skin}`}>
                  <Icon className={`w-8 h-8 ${iconColor}`} />
                  <div>
                    <div className={`text-lg font-bold ${titleColor}`}>{title}</div>
                    <div className="text-xs text-slate-400">{msg}</div>
                  </div>
                  <div className="ml-auto text-right">
                    <div className="text-2xl font-bold font-mono text-white">{stats.curRps.toFixed(1)}</div>
                    <div className="text-[11px] text-slate-500">req/s now</div>
                  </div>
                </div>
              );
            })()}

            {/* First-trigger banner — first blocking/distress response */}
            {firstTrigger && (() => {
              const c = firstTrigger.code;
              const label = c === 429 ? 'rate-limited by F5 XC (HTTP 429)'
                : c === 403 ? 'blocked / challenged by F5 XC (HTTP 403)'
                : `origin distress (HTTP ${c})`;
              const detail = c === 429 || c === 403
                ? `F5 XC started mitigating at the edge after ~${firstTrigger.reqs} requests at ~${rps} req/s — Rate Limiting / block is working.`
                : `Origin began returning ${c} after ~${firstTrigger.reqs} requests at ~${rps} req/s. Sustain ~100+ RPS with the DDoS RPS threshold lowered for L7 DDoS auto-mitigation to engage.`;
              return (
                <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 flex items-center gap-3">
                  <Zap className="w-6 h-6 text-amber-400 shrink-0" />
                  <div>
                    <div className="font-bold text-amber-300">First trigger at {(firstTrigger.ms / 1000).toFixed(1)}s — {label}</div>
                    <div className="text-xs text-slate-400">{detail}</div>
                  </div>
                </div>
              );
            })()}

            {running && !firstTrigger && stats && (
              <div className="rounded-xl border border-slate-700/50 bg-slate-800/40 p-4 flex items-center gap-3 text-sm text-slate-400">
                <HeartPulse className="w-5 h-5 text-emerald-400 shrink-0 animate-pulse" />
                Sustaining ~{stats.curRps.toFixed(1)} req/s… no blocking yet. Watching for the first 429 / 403 (F5 mitigation) or 5xx (origin distress).
              </div>
            )}

            {/* Stat cards */}
            {stats && (
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                {[
                  { label: 'Total sent', value: stats.total, color: 'text-white' },
                  { label: 'Healthy (2xx/3xx)', value: stats.ok, color: 'text-emerald-400' },
                  { label: 'F5 blocked (429/403)', value: stats.blocked, color: 'text-blue-400' },
                  { label: '5xx distress', value: stats.serverErr, color: 'text-red-400' },
                  { label: 'Avg latency', value: `${Math.round(stats.avg)}ms`, color: 'text-amber-400' },
                  { label: 'P95 latency', value: `${Math.round(stats.p95)}ms`, color: 'text-purple-400' },
                ].map((c, i) => (
                  <div key={i} className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-4">
                    <p className="text-xs text-slate-500 mb-1">{c.label}</p>
                    <p className={`text-2xl font-bold font-mono ${c.color}`}>{c.value}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Chart */}
            {chartData.length > 1 && (
              <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
                <h3 className="text-sm font-semibold text-slate-300 mb-4">Traffic vs. origin distress</h3>
                <ResponsiveContainer width="100%" height={280}>
                  <ComposedChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                    <YAxis yAxisId="left" stroke="#64748b" fontSize={11} />
                    <YAxis yAxisId="right" orientation="right" stroke="#64748b" fontSize={11} domain={[0, 100]} unit="%" />
                    <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                    <Bar yAxisId="left" dataKey="rps" name="RPS" fill="#3b82f6" fillOpacity={0.5} />
                    <Area yAxisId="right" dataKey="errPct" name="Error %" fill="#ef4444" fillOpacity={0.15} stroke="#ef4444" strokeWidth={2} />
                    <Line yAxisId="left" dataKey="latency" name="Avg latency (ms)" stroke="#f59e0b" strokeWidth={2} dot={false} />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* Status distribution */}
            {stats && (
              <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
                <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2"><Activity className="w-4 h-4" /> Status code distribution</h3>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(stats.dist).sort((a, b) => b[1] - a[1]).map(([code, n]) => (
                    <div key={code} className="px-3 py-2 bg-slate-900/50 rounded-lg border border-slate-700/50">
                      <span className={`font-mono font-bold ${statusColor(code === 'ERR' ? 0 : +code)}`}>{code}</span>
                      <span className="text-slate-400 text-sm ml-2">{n}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!stats && !running && (
              <div className="text-center py-14 text-slate-500">
                <Rocket className="w-10 h-10 mx-auto mb-3 opacity-40" />
                <p>Set your target (Step 1), pick a sustained RPS (Step 2), then Start (Step 3) and watch for the trigger.</p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function StepCard({ n, title, children }: { n: number; title: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
      <div className="flex items-center gap-2.5 mb-4">
        <span className="shrink-0 w-6 h-6 rounded-full bg-red-500/15 text-red-300 flex items-center justify-center text-sm font-bold">{n}</span>
        <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
      </div>
      {children}
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-slate-400 mb-1.5">{label}</label>
      {children}
      {hint && <p className="text-[10px] text-slate-600 mt-1">{hint}</p>}
    </div>
  );
}

export default DdosTester;
