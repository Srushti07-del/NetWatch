import { Shield } from 'lucide-react';
import { PlaceholderPage } from '../components/ui/PlaceholderPage';

export function ThreatDetectionPage() {
  return (
    <PlaceholderPage
      title="Threat Detection"
      description="Security events, anomaly detection, and alert management"
      icon={<Shield size={28} />}
      features={[
        'Alert feed with severity tiers',
        'Rule-based detection engine',
        'Anomaly scoring',
        'Threat correlation',
        'Alert suppression rules',
        'Incident history log',
      ]}
    />
  );
}
