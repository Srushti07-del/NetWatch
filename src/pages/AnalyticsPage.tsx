import { BarChart3 } from 'lucide-react';
import { PlaceholderPage } from '../components/ui/PlaceholderPage';

export function AnalyticsPage() {
  return (
    <PlaceholderPage
      title="Analytics"
      description="Traffic patterns, trend analysis, and reporting"
      icon={<BarChart3 size={28} />}
      features={[
        'Historical traffic trends',
        'Top talkers report',
        'Protocol trend charts',
        'Scheduled reports',
        'Custom time range selection',
        'CSV / PDF export',
      ]}
    />
  );
}
