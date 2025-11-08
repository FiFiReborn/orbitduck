# 🧩 OrbitDuck Database Schema

This entity-relationship diagram represents the database model used by OrbitDuck.  
It defines all major entities, their attributes, and relationships between them.

```mermaid
erDiagram
  TARGETS ||--o{ ASSETS : has
  ASSETS ||--o{ SERVICES : exposes
  ASSETS ||--o{ PROFILES : has
  SERVICES ||--o{ FINDINGS : yields
  SERVICES ||--o{ RULE_HITS : triggers
  SERVICES ||--o{ SCORES : scored
  SERVICES ||--o{ EVIDENCE : evidenced_by
  SERVICES ||--o{ OBSERVATIONS : observed_as
  FINDINGS ||--o{ CVE_LINKS : links_to
  SNAPSHOTS ||--o{ SNAPSHOT_ITEMS : captures
  SNAPSHOTS ||--o{ DELTAS : diffs_produce
  DELTAS }o--|| SNAPSHOTS : compares_to
  ALERTS }o--|| SERVICES : about
  ALERTS }o--o{ RULE_HITS : includes
  REPORTS }o--|| SNAPSHOTS : generated_from
  EVENT_LOG }o--|| TARGETS : records
  EVENT_LOG }o--|| ASSETS : records
  EVENT_LOG }o--|| SERVICES : records
  RULES ||--o{ RULE_HITS : defines
  CONFIG }o--|| SERVICES : configures
  API_KEYS }o--|| SERVICES : authenticates


  TARGETS {
    INTEGER id PK
    TEXT input
    TEXT type
    TEXT created_at
  }

  ASSETS {
    INTEGER id PK
    INTEGER target_id FK
    TEXT fqdn
    TEXT ip
    REAL confidence
    TEXT first_seen
    TEXT last_seen
    TEXT tags
    TEXT source
  }

  PROFILES {
    INTEGER id PK
    INTEGER asset_id FK
    TEXT asn
    TEXT provider
    TEXT region
    TEXT geo
    TEXT whois
    INTEGER cert_age_days
    TEXT updated_at
  }

  SERVICES {
    INTEGER id PK
    INTEGER asset_id FK
    INTEGER port
    TEXT proto
    TEXT name
    TEXT banner
    TEXT tech_guess
    INTEGER internet_facing
    TEXT first_seen
    TEXT last_seen
  }

  OBSERVATIONS {
    INTEGER id PK
    INTEGER service_id FK
    TEXT kind
    TEXT value
    TEXT source
    REAL confidence
    TEXT ts
  }

  FINDINGS {
    INTEGER id PK
    INTEGER service_id FK
    TEXT kind
    TEXT value
    REAL confidence
    TEXT evidence_ids
    TEXT created_at
  }

  CVE_LINKS {
    INTEGER id PK
    INTEGER finding_id FK
    TEXT cve_id
    REAL cvss_base
    TEXT attack_vector
    INTEGER exploit_available
    TEXT published_date
  }

  RULES {
    INTEGER id PK
    TEXT name
    TEXT severity
    TEXT logic
    TEXT enabled_at
  }

  RULE_HITS {
    INTEGER id PK
    INTEGER service_id FK
    INTEGER rule_id FK
    TEXT rationale
    TEXT evidence_ids
    TEXT triggered_at
  }

  SCORES {
    INTEGER id PK
    INTEGER service_id FK
    REAL exposure
    REAL severity
    REAL exploitability
    REAL business_impact
    REAL change_risk
    REAL total
    TEXT computed_at
  }

  EVIDENCE {
    INTEGER id PK
    INTEGER service_id FK
    TEXT kind
    TEXT ref
    TEXT captured_at
  }

  SNAPSHOTS {
    INTEGER id PK
    TEXT label
    TEXT created_at
  }

  SNAPSHOT_ITEMS {
    INTEGER id PK
    INTEGER snapshot_id FK
    TEXT entity_type
    INTEGER entity_id
    TEXT hash
  }

  DELTAS {
    INTEGER id PK
    INTEGER snapshot_id FK
    INTEGER prev_snapshot_id FK
    TEXT entity_type
    INTEGER entity_id
    TEXT change_type
    TEXT diff
  }

  ALERTS {
    INTEGER id PK
    INTEGER service_id FK
    TEXT severity
    TEXT summary
    TEXT payload
    TEXT created_at
    INTEGER sent
  }

  REPORTS {
    INTEGER id PK
    INTEGER snapshot_id FK
    TEXT format
    TEXT path
    TEXT created_at
  }

  EVENT_LOG {
    INTEGER id PK
    TEXT who
    TEXT what
    TEXT entity_type
    INTEGER entity_id
    TEXT payload
    TEXT ts
  }

  CONFIG {
    INTEGER id PK
    TEXT key
    TEXT value
  }

  API_KEYS {
    INTEGER id PK
    TEXT provider
    TEXT key_encrypted
    TEXT updated_at
  }
