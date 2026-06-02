import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppProvider } from './context/AppContext';
import { ToastProvider } from './context/ToastContext';
import { ThemeProvider } from './context/ThemeContext';
import { Header } from './components/Header';
import Footer from './components/Footer';
import { Home } from './pages/Home';
import { WAFScanner } from './pages/WAFScanner';
import { ConfigVisualizer } from './pages/ConfigVisualizer';
import { CopyConfig } from './pages/CopyConfig';
import { SecurityAuditor } from './pages/SecurityAuditor';
import { PropertyViewer } from './pages/PropertyViewer';
import { ConfigComparator } from './pages/ConfigComparator';
import { HttpSanityChecker } from './pages/HttpSanityChecker';
import { PrefixBuilder } from './pages/PrefixBuilder';
import { HttpLbForge } from './pages/HttpLbForge';
import { TimeTracker } from './pages/TimeTracker';
import { RateLimitAdvisor } from './pages/RateLimitAdvisor';
import { RateLimitExplainer } from './pages/RateLimitExplainer';
import FPAnalyzer from './pages/FPAnalyzer';
import { ConfigDump } from './pages/ConfigDump';
import { ConfigExplorer } from './pages/ConfigExplorer';
import { DdosAdvisor } from './pages/DdosAdvisor';
import { LogAnalyzer } from './pages/LogAnalyzer';
import LoadTester from './pages/LoadTester';
import { SOCLobby } from './pages/SOCLobby';
import { SOCRoom } from './pages/SOCRoom';
import { APIShieldAdvisor } from './pages/APIShieldAdvisor';
import { APIReport } from './pages/APIReport';
import { Anonymizer } from './pages/Anonymizer';
import { DiffChecker } from './pages/DiffChecker';
import {
  WAFScannerExplainer, SecurityAuditorExplainer, FPAnalyzerExplainer,
  DDoSAdvisorExplainer, ConfigViewerExplainer, ConfigComparatorExplainer,
  DependencyMapExplainer, HttpSanityExplainer, LogAnalyzerExplainer,
} from './pages/ToolExplainers';
import {
  LoadTesterExplainer, APIShieldExplainer, APIReportExplainer,
  SOCRoomExplainer, PrefixBuilderExplainer, CopyConfigExplainer,
  PropertyViewerExplainer, HttpLbForgeExplainer, ConfigDumpExplainer,
} from './pages/ToolExplainersPart2';

function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <AppProvider>
          <ToastProvider>
            <div className="min-h-screen bg-slate-900">
              <Header />
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/waf-scanner" element={<WAFScanner />} />
                <Route path="/config-visualizer" element={<ConfigVisualizer />} />
                <Route path="/copy-config" element={<CopyConfig />} />
                <Route path="/security-auditor" element={<SecurityAuditor />} />
                <Route path="/property-viewer" element={<PropertyViewer />} />
                <Route path="/config-comparator" element={<ConfigComparator />} />
                <Route path="/http-sanity-checker" element={<HttpSanityChecker />} />
                <Route path="/prefix-builder" element={<PrefixBuilder />} />
                <Route path="/http-lb-forge" element={<HttpLbForge />} />
                <Route path="/time-tracker" element={<TimeTracker />} />
                <Route path="/rate-limit-advisor" element={<RateLimitAdvisor />} />
                <Route path="/rate-limit-explainer" element={<RateLimitExplainer />} />
                <Route path="/fp-analyzer" element={<FPAnalyzer />} />
                <Route path="/config-dump" element={<ConfigDump />} />
                <Route path="/config-explorer" element={<ConfigExplorer />} />
                <Route path="/ddos-advisor" element={<DdosAdvisor />} />
                <Route path="/log-analyzer" element={<LogAnalyzer />} />
                <Route path="/load-tester" element={<LoadTester />} />
                <Route path="/soc-lobby" element={<SOCLobby />} />
                <Route path="/soc-room/:roomId" element={<SOCRoom />} />
                <Route path="/api-shield" element={<APIShieldAdvisor />} />
                <Route path="/api-report" element={<APIReport />} />
                <Route path="/anonymizer" element={<Anonymizer />} />
                <Route path="/diff-checker" element={<DiffChecker />} />
                {/* Tool Explainer Pages */}
                <Route path="/explainer/waf-scanner" element={<WAFScannerExplainer />} />
                <Route path="/explainer/security-auditor" element={<SecurityAuditorExplainer />} />
                <Route path="/explainer/fp-analyzer" element={<FPAnalyzerExplainer />} />
                <Route path="/explainer/ddos-advisor" element={<DDoSAdvisorExplainer />} />
                <Route path="/explainer/config-viewer" element={<ConfigViewerExplainer />} />
                <Route path="/explainer/config-comparator" element={<ConfigComparatorExplainer />} />
                <Route path="/explainer/dependency-map" element={<DependencyMapExplainer />} />
                <Route path="/explainer/config-dump" element={<ConfigDumpExplainer />} />
                <Route path="/explainer/http-sanity" element={<HttpSanityExplainer />} />
                <Route path="/explainer/log-analyzer" element={<LogAnalyzerExplainer />} />
                <Route path="/explainer/load-tester" element={<LoadTesterExplainer />} />
                <Route path="/explainer/api-shield" element={<APIShieldExplainer />} />
                <Route path="/explainer/api-report" element={<APIReportExplainer />} />
                <Route path="/explainer/soc-room" element={<SOCRoomExplainer />} />
                <Route path="/explainer/prefix-builder" element={<PrefixBuilderExplainer />} />
                <Route path="/explainer/copy-config" element={<CopyConfigExplainer />} />
                <Route path="/explainer/property-viewer" element={<PropertyViewerExplainer />} />
                <Route path="/explainer/http-lb-forge" element={<HttpLbForgeExplainer />} />
              </Routes>
              <Footer />
            </div>
          </ToastProvider>
        </AppProvider>
      </ThemeProvider>
    </BrowserRouter>
  );
}

export default App;