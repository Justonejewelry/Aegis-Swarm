-- AEGIS Swarm core schema (PostgreSQL)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS engagements (
  engagement_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  mode TEXT NOT NULL,
  status TEXT NOT NULL,
  scope JSONB NOT NULL,
  approver TEXT,
  start_at TIMESTAMPTZ,
  end_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings (
  finding_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  engagement_id UUID NOT NULL REFERENCES engagements(engagement_id),
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  risk_score REAL NOT NULL DEFAULT 0,
  mitre_techniques TEXT[] DEFAULT '{}',
  cves TEXT[] DEFAULT '{}',
  assets TEXT[] DEFAULT '{}',
  sources TEXT[] NOT NULL,
  remediation TEXT[] DEFAULT '{}',
  evidence_refs TEXT[] DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(risk_score DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  audit_id BIGSERIAL PRIMARY KEY,
  engagement_id UUID,
  agent_id TEXT NOT NULL,
  event TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_engagement ON audit_log(engagement_id);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);

CREATE TABLE IF NOT EXISTS agent_registry (
  agent_id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  version TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'registered',
  last_heartbeat TIMESTAMPTZ,
  meta JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS assets (
  asset_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  hostname TEXT,
  ip INET,
  cloud_id TEXT,
  criticality REAL NOT NULL DEFAULT 0.5,
  tags TEXT[] DEFAULT '{}',
  last_seen TIMESTAMPTZ,
  meta JSONB NOT NULL DEFAULT '{}'
);

-- Privilege / attack-path graph edges (NetworkX persistence)
CREATE TABLE IF NOT EXISTS graph_edges (
  edge_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  engagement_id UUID NOT NULL,
  src TEXT NOT NULL,
  dst TEXT NOT NULL,
  relation TEXT DEFAULT 'related',
  meta JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_graph_engagement ON graph_edges(engagement_id);
CREATE INDEX IF NOT EXISTS idx_graph_src ON graph_edges(src);
CREATE INDEX IF NOT EXISTS idx_graph_dst ON graph_edges(dst);
