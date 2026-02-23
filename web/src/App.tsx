import { useRef, useCallback, useState, lazy, Suspense } from 'react';
const IPManagement = lazy(() => import('./components/IPManagement'));
const LogViewer = lazy(() => import('./components/LogViewer'));
import { Container, Box } from '@mui/material';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { SiteList, SiteListRef } from './components/SiteList';
import { SiteForm } from './components/SiteForm';
import { Login } from './components/Login';
import VirusTotalStats from './components/VirusTotalStats';
import { AuthProvider, useAuth } from './context/AuthContext';
import PatternManagement from './components/PatternManagement';
import CertificateManager from './components/CertificateManager';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { checkAuth } = useAuth();
  
  if (!checkAuth()) {
    return <Navigate to="/login" />;
  }

  return <>{children}</>;
}

function SitesPage() {
  const siteListRef = useRef<SiteListRef>(null);
  const [certRefreshToken, setCertRefreshToken] = useState(0);
  const { role } = useAuth();

  const handleSiteAdded = useCallback(() => {
    console.log('handleSiteAdded called, forcing refresh');
    // Call refresh method on SiteList
    if (siteListRef.current) {
      siteListRef.current.refresh();
    }
  }, []);

  const handleCertificatesChanged = useCallback(() => {
    setCertRefreshToken((prev) => prev + 1);
  }, []);

  return (
    <Container>
      <Box sx={{ mb: 4 }}>
        <VirusTotalStats />
      </Box>
      {role === 'super_admin' && (
        <CertificateManager onCertificatesChanged={handleCertificatesChanged} />
      )}
      <SiteForm
        onSiteAdded={handleSiteAdded}
        certRefreshToken={certRefreshToken}
        currentUserRole={role}
      />
      <Box sx={{ mt: 4 }}>
        <SiteList ref={siteListRef} />
      </Box>
    </Container>
  );
}

function App() {
  return (
    <BrowserRouter basename="/admin-ui">
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/sites"
            element={
              <ProtectedRoute>
                <SitesPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/ip-management"
            element={
              <ProtectedRoute>
                <Suspense fallback={<div>Loading...</div>}>
                  <IPManagement />
                </Suspense>
              </ProtectedRoute>
            }
          />
          <Route
            path="/patterns"
            element={
              <ProtectedRoute>
                <Suspense fallback={<div>Loading...</div>}>
                  <PatternManagement />
                </Suspense>
              </ProtectedRoute>
            }
          />
          <Route
            path="/logs"
            element={
              <ProtectedRoute>
                <Suspense fallback={<div>Loading...</div>}>
                  <LogViewer />
                </Suspense>
              </ProtectedRoute>
            }
          />
          <Route path="/" element={<Navigate to="/sites" />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
