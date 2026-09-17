CREATE TABLE login_events (
 event_id TEXT PRIMARY KEY,
 event_time TEXT NOT NULL,
 user_name TEXT NOT NULL,
 source_ip TEXT NOT NULL,
 result TEXT NOT NULL CHECK (result IN ('success', 'failure'))
);
CREATE TABLE assets (
 source_ip TEXT PRIMARY KEY,
 hostname TEXT NOT NULL,
 owner_team TEXT NOT NULL
);
INSERT INTO assets VALUES ('192.0.2.10', 'training-workstation', 'Training');
INSERT INTO login_events VALUES
 ('E01','2026-01-01T10:00:00Z','lab-user','198.51.100.20','failure'),
 ('E02','2026-01-01T10:01:00Z','lab-user','198.51.100.20','failure'),
 ('E03','2026-01-01T10:02:00Z','lab-user','198.51.100.20','failure'),
 ('E04','2026-01-01T10:03:00Z','lab-user','198.51.100.20','success'),
 ('E05','2026-01-01T10:04:00Z','benign-user','192.0.2.10','success'),
 ('E06','2026-01-01T10:05:00Z','benign-user','192.0.2.10','failure');
