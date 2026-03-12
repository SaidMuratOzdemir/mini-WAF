import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Login } from './components/Login';
import { AuthProvider, useAuth } from './context/AuthContext';
import AppLayout from './components/AppLayout';
import { TooltipProvider } from './components/ui/tooltip';
import { Loader2 } from 'lucide-react';

const SitesPage = lazy(() => import('./components/SitesPage'));
const IPManagement = lazy(() => import('./components/IPManagement'));
const PatternManagement = lazy(() => import('./components/PatternManagement'));
const LogViewer = lazy(() => import('./components/LogViewer'));
const OutboundProxyManagement = lazy(() => import('./components/OutboundProxyManagement'));

function PageLoader() {
  return (
    <div className="flex h-full items-center justify-center">
      <Loader2 className="h-8 w-8 animate-spin text-emerald-400" />
    </div>
  );
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { checkAuth } = useAuth();
  if (!checkAuth()) {
    return <Navigate to="/login" />;
  }
  return <>{children}</>;
}

function App() {
  return (
    <BrowserRouter basename="/admin-ui">
      <AuthProvider>
        <TooltipProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route
              element={
                <ProtectedRoute>
                  <AppLayout />
                </ProtectedRoute>
              }
            >
              <Route
                path="/sites"
                element={<Suspense fallback={<PageLoader />}><SitesPage /></Suspense>}
              />
              <Route
                path="/ip-management"
                element={<Suspense fallback={<PageLoader />}><IPManagement /></Suspense>}
              />
              <Route
                path="/patterns"
                element={<Suspense fallback={<PageLoader />}><PatternManagement /></Suspense>}
              />
              <Route
                path="/logs"
                element={<Suspense fallback={<PageLoader />}><LogViewer /></Suspense>}
              />
              <Route
                path="/forward-proxy"
                element={<Suspense fallback={<PageLoader />}><OutboundProxyManagement /></Suspense>}
              />
            </Route>
            <Route path="/" element={<Navigate to="/sites" />} />
          </Routes>
        </TooltipProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
