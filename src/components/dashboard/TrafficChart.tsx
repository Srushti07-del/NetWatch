/**
 * TrafficChart.tsx
 * Interactive line chart showing incoming vs outgoing traffic over time.
 */
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { TrafficDataPoint } from '../../types';

interface TrafficChartProps {
  data: TrafficDataPoint[];
}

interface TooltipPayloadItem {
  color: string;
  name: string;
  value: number;
}

function CustomTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: TooltipPayloadItem[];
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div
      style={{
        background: '#192438',
        border: '1px solid #1E2D45',
        borderRadius: 8,
        padding: '10px 14px',
        fontSize: 12,
      }}
    >
      <p style={{ color: '#94A3B8', marginBottom: 6, fontWeight: 600 }}>{label}</p>
      {payload.map((p) => (
        <div key={p.name} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
          <div style={{ width: 8, height: 8, borderRadius: 2, background: p.color }} />
          <span style={{ color: '#94A3B8' }}>{p.name}:</span>
          <span style={{ color: '#F1F5F9', fontWeight: 600 }}>{p.value} Mbps</span>
        </div>
      ))}
    </div>
  );
}

export function TrafficChart({ data }: TrafficChartProps) {
  return (
    <div
      style={{
        background: '#141F30',
        border: '1px solid #1E2D45',
        borderRadius: 12,
        padding: '20px',
      }}
    >
      <div style={{ marginBottom: 16 }}>
        <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 14, fontWeight: 600 }}>
          Network Traffic
        </h3>
        <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 12 }}>
          Incoming vs outgoing bandwidth (Mbps) — illustrative sample data
        </p>
      </div>
      <ResponsiveContainer width="100%" height={260}>
        <LineChart data={data} margin={{ top: 4, right: 8, left: -8, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1E2D45" vertical={false} />
          <XAxis
            dataKey="time"
            tick={{ fill: '#64748B', fontSize: 11 }}
            axisLine={{ stroke: '#1E2D45' }}
            tickLine={false}
            interval={3}
          />
          <YAxis
            tick={{ fill: '#64748B', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            tickFormatter={(v: number) => `${v}`}
            unit=" Mbps"
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend
            wrapperStyle={{ fontSize: 12, color: '#94A3B8', paddingTop: 12 }}
            iconType="circle"
            iconSize={8}
          />
          <Line
            type="monotone"
            dataKey="incoming"
            name="Incoming"
            stroke="#42D6C5"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4, fill: '#42D6C5' }}
          />
          <Line
            type="monotone"
            dataKey="outgoing"
            name="Outgoing"
            stroke="#3B82F6"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4, fill: '#3B82F6' }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
