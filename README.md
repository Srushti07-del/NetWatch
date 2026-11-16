# NetWatch

Network Security Monitoring and Traffic Analysis Platform.

## Project Overview

NetWatch is being developed to monitor network traffic, inspect packets, identify devices, analyze connections, and detect suspicious network activity. The goal is to provide visibility into what is happening on a network, who is connected, and what those connections are doing.

## Planned Features

- **Network Overview Dashboard** — high-level view of traffic volume, active connections, and device counts.
- **Live Traffic Monitoring** — real-time view of packets moving across the network.
- **Device Discovery** — identification of devices on the network.
- **Connection Monitoring** — tracking of active and historical network connections.
- **Threat Detection** — identification of suspicious or malicious network activity.
- **Network Analytics** — charts and reports on traffic patterns over time.

## Development Status

### Implemented (frontend only)

The frontend is implemented and includes the following pages and components:

- **Overview** — network summary with metric cards and traffic charts.
- **Live Traffic** — illustrative traffic feed.
- **Devices** — device listing.
- **Connections** — connection listing.
- **Threat Detection** — security events listing.
- **Analytics** — traffic analytics charts.
- **Settings** — application settings placeholder.
- **Layout** — sidebar navigation and header.

The frontend currently uses isolated illustrative mock data in `src/data/mockData.ts` and is **not yet connected to a real packet-capture engine**.

### Planned (backend)

The following backend work is planned and is **not yet implemented**:

- **Python + FastAPI** backend exposing REST endpoints for the frontend.
- Real network packet capture and inspection engine.
- Live data streaming from the backend to the frontend via WebSockets or polling.
- Persistent storage of devices, connections, and security events.

## Technology Stack

- **React** — UI library
- **TypeScript** — type-safe JavaScript
- **Vite** — build tool and dev server
- **Tailwind CSS** — styling
- **Recharts** — charts and data visualization
- **Lucide React** — icons
- **Python + FastAPI** — planned backend (not yet implemented)

## Getting Started

### Prerequisites

- Node.js (recommended 18 or newer)

### Installation

```bash
npm install
```

### Development

Start the Vite dev server:

```bash
npm run dev
```

The app will be available at `http://localhost:5173` by default.

### Build

Type-check and build for production:

```bash
npm run build
```

### Lint

Run Oxlint:

```bash
npm run lint
```

### Preview

Preview the production build locally:

```bash
npm run preview
```

## Project Structure

```
netwatch/
├── public/
│   ├── favicon.svg
│   └── icons.svg
├── src/
│   ├── main.tsx              # Vite entry point
│   ├── index.css             # Global styles and Tailwind theme
│   ├── App.tsx               # Root router configuration
│   ├── App.css
│   ├── assets/
│   │   ├── hero.png
│   │   ├── react.svg
│   │   └── vite.svg
│   ├── components/
│   │   ├── layout/
│   │   │   ├── AppLayout.tsx
│   │   │   ├── Header.tsx
│   │   │   └── Sidebar.tsx
│   │   ├── dashboard/
│   │   │   ├── ActivityTable.tsx
│   │   │   ├── MetricCard.tsx
│   │   │   ├── ProtocolChart.tsx
│   │   │   ├── SecurityEvents.tsx
│   │   │   └── TrafficChart.tsx
│   │   └── ui/
│   │       └── PlaceholderPage.tsx
│   ├── pages/
│   │   ├── AnalyticsPage.tsx
│   │   ├── ConnectionsPage.tsx
│   │   ├── DevicesPage.tsx
│   │   ├── LiveTrafficPage.tsx
│   │   ├── OverviewPage.tsx
│   │   ├── SettingsPage.tsx
│   │   └── ThreatDetectionPage.tsx
│   ├── data/
│   │   └── mockData.ts       # Illustrative mock data (frontend only)
│   ├── hooks/
│   │   └── useApi.ts
│   ├── lib/
│   │   └── formatters.ts
│   ├── services/
│   │   └── api/
│   │       └── index.ts
│   └── types/
│       └── index.ts
├── index.html
├── package.json
├── vite.config.ts
├── tsconfig.json
├── tsconfig.app.json
├── tsconfig.node.json
├── .oxlintrc.json
└── .gitignore
```

## Future Development

The next phase of development is to replace the mock data with a real backend:

- Implement a **Python + FastAPI** API that the frontend calls instead of using mock data.
- Integrate a real **network packet-capture engine** to inspect live traffic.
- Wire up the frontend pages to live backend data so device discovery, connection monitoring, and threat detection reflect actual network activity.
