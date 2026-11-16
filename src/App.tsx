/**
 * App.tsx
 * Root router configuration for NetWatch.
 */
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AppLayout } from './components/layout/AppLayout';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { ConnectionsPage } from './pages/ConnectionsPage';
import { DevicesPage } from './pages/DevicesPage';
import { LiveTrafficPage } from './pages/LiveTrafficPage';
import { OverviewPage } from './pages/OverviewPage';
import { SettingsPage } from './pages/SettingsPage';
import { ThreatDetectionPage } from './pages/ThreatDetectionPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<OverviewPage />} />
          <Route path="live-traffic"  element={<LiveTrafficPage />} />
          <Route path="devices"       element={<DevicesPage />} />
          <Route path="connections"   element={<ConnectionsPage />} />
          <Route path="threats"       element={<ThreatDetectionPage />} />
          <Route path="analytics"     element={<AnalyticsPage />} />
          <Route path="settings"      element={<SettingsPage />} />
          {/* Catch-all → back to overview */}
          <Route path="*"             element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
