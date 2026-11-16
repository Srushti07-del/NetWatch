import { Cpu } from 'lucide-react';
import { PlaceholderPage } from '../components/ui/PlaceholderPage';

export function DevicesPage() {
  return (
    <PlaceholderPage
      title="Devices"
      description="Discovered network endpoints and their status"
      icon={<Cpu size={28} />}
      features={[
        'Device discovery',
        'OS fingerprinting',
        'Open port listing',
        'Per-device traffic stats',
        'Device grouping',
        'Historical presence',
      ]}
    />
  );
}
