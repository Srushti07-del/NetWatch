/**
 * ProtocolChart.tsx
 * Donut chart showing protocol distribution.
 */
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import type { ProtocolDataPoint } from '../../types';
import { formatCompact } from '../../lib/formatters';

interface ProtocolChartProps {
  data: ProtocolDataPoint[];
}

interface TooltipPayloadItem {
  payload: ProtocolDataPoint;
  value: number;
}

function CustomTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: TooltipPayloadItem[];
}) {
  if (!active || !payload?.length) return null;
  const { protocol, value, percentage, color } = payload[0].payload;
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
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
        <div style={{ width: 8, height: 8, borderRadius: 2, background: color }} />
        <span style={{ color: '#F1F5F9', fontWeight: 600 }}>{protocol}</span>
      </div>
      <div style={{ color: '#94A3B8' }}>Packets: <span style={{ color: '#F1F5F9' }}>{formatCompact(value)}</span></div>
      <div style={{ color: '#94A3B8' }}>Share: <span style={{ color: '#F1F5F9' }}>{percentage}%</span></div>
    </div>
  );
}

export function ProtocolChart({ data }: ProtocolChartProps) {
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
          Protocol Distribution
        </h3>
        <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 12 }}>
          Traffic breakdown by protocol — illustrative sample data
        </p>
      </div>

      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={90}
            paddingAngle={2}
            dataKey="value"
            nameKey="protocol"
            strokeWidth={0}
          >
            {data.map((entry) => (
              <Cell key={entry.protocol} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
        </PieChart>
      </ResponsiveContainer>

      {/* Legend */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 8 }}>
        {data.map((entry) => (
          <div key={entry.protocol} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div
              style={{
                width: 10,
                height: 10,
                borderRadius: 2,
                background: entry.color,
                flexShrink: 0,
              }}
            />
            <span style={{ color: '#94A3B8', fontSize: 12, flex: 1 }}>{entry.protocol}</span>
            <span style={{ color: '#94A3B8', fontSize: 12, fontVariantNumeric: 'tabular-nums' }}>
              {entry.percentage}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
