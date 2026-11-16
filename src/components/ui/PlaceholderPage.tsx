/**
 * PlaceholderPage.tsx
 * Shared component for pages that are planned but not yet implemented.
 */
import type { ReactNode } from 'react';

interface PlaceholderPageProps {
  title: string;
  description: string;
  icon: ReactNode;
  features: string[];
}

export function PlaceholderPage({ title, description, icon, features }: PlaceholderPageProps) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div>
        <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
          {title}
        </h2>
        <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
          {description}
        </p>
      </div>

      {/* Coming-soon panel */}
      <div
        style={{
          background: '#141F30',
          border: '1px solid #1E2D45',
          borderRadius: 12,
          padding: '48px 32px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          textAlign: 'center',
          gap: 20,
        }}
      >
        <div
          style={{
            width: 64,
            height: 64,
            borderRadius: 16,
            background: 'rgba(66, 214, 197, 0.08)',
            border: '1px solid rgba(66, 214, 197, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#42D6C5',
          }}
        >
          {icon}
        </div>

        <div>
          <h3 style={{ margin: '0 0 8px', color: '#F1F5F9', fontSize: 16, fontWeight: 600 }}>
            {title} — Coming Soon
          </h3>
          <p style={{ margin: 0, color: '#94A3B8', fontSize: 13, maxWidth: 480 }}>
            This section is under development. It will provide detailed visibility into{' '}
            {description.toLowerCase()}.
          </p>
        </div>

        {/* Planned features */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: 10,
            width: '100%',
            maxWidth: 600,
          }}
        >
          {features.map((f) => (
            <div
              key={f}
              style={{
                background: '#0D1726',
                border: '1px solid #1E2D45',
                borderRadius: 8,
                padding: '10px 14px',
                color: '#64748B',
                fontSize: 12,
                textAlign: 'left',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <div
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background: '#1E2D45',
                  flexShrink: 0,
                }}
              />
              {f}
            </div>
          ))}
        </div>

        <div
          style={{
            background: 'rgba(66, 214, 197, 0.06)',
            border: '1px solid rgba(66, 214, 197, 0.12)',
            borderRadius: 8,
            padding: '8px 16px',
            color: '#42D6C5',
            fontSize: 12,
          }}
        >
          Requires FastAPI backend integration
        </div>
      </div>
    </div>
  );
}
