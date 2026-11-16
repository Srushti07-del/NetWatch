import { Activity } from 'lucide-react';
import { PlaceholderPage } from '../components/ui/PlaceholderPage';

export function LiveTrafficPage() {
  return (
    <PlaceholderPage
      title="Live Traffic"
      description="Real-time packet capture and flow inspection"
      icon={<Activity size={28} />}
      features={[
        'Real-time packet stream',
        'Deep packet inspection',
        'Flow tracking',
        'Bandwidth heatmap',
        'Filter by protocol / host',
        'Packet export (PCAP)',
      ]}
    />
  );
}
