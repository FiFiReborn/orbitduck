# 🧩 OrbitDuck Database Schema

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
