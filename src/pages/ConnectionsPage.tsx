import { GitBranch } from 'lucide-react';
import { PlaceholderPage } from '../components/ui/PlaceholderPage';

export function ConnectionsPage() {
  return (
    <PlaceholderPage
      title="Connections"
      description="Active and historical network flows between hosts"
      icon={<GitBranch size={28} />}
      features={[
        'Active connection list',
        'Session duration tracking',
        'Bytes transferred',
        'Connection state timeline',
        'Geo-IP mapping',
        'Connection graph visualization',
      ]}
    />
  );
}
