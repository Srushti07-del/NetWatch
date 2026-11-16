import { Settings } from 'lucide-react';
import { PlaceholderPage } from '../components/ui/PlaceholderPage';

export function SettingsPage() {
  return (
    <PlaceholderPage
      title="Settings"
      description="Application configuration and monitoring preferences"
      icon={<Settings size={28} />}
      features={[
        'Network interface selection',
        'Capture filter rules',
        'Alert thresholds',
        'Notification channels',
        'API backend connection',
        'User preferences',
      ]}
    />
  );
}
