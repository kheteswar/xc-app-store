export function Footer() {
  return (
    <footer className="border-t border-slate-800 pt-6 pb-12">
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">XC App Store</span>
            <span className="px-2 py-0.5 bg-slate-800 rounded text-xs text-slate-500 font-mono">v1.0.0</span>
          </div>
          <p className="text-sm text-slate-500">This app store is not affiliated with or endorsed by F5, Inc. F5 and its logos are trademarks of F5, Inc.; all rights reserved. Use at your own risk.</p>
          <div className="flex items-center gap-4 text-sm">
            <a
              href="https://docs.cloud.f5.com/docs-v2/api"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-400 hover:text-slate-200 transition-colors"
            >
              F5 XC API Docs
            </a>
            <span className="text-slate-600">-</span>
            <a
              href="https://github.com/kheteswar/xc-app-store"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-400 hover:text-slate-200 transition-colors"
            >
              GitHub
            </a>
          </div>
        </div>
        <div className="mt-4 text-center">
          <span className="text-xs text-slate-500">
            Developed with love by{' '}
            <a
              href="https://coderyogi.com/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-300 hover:text-white underline"
            >
              coderyogi
            </a>
          </span>
        </div>
      </div>
    </footer>
  );
}

export default Footer;
