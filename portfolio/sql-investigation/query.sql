-- All timestamps are normalized UTC. Window includes exactly 10 minutes ago,
-- excludes events at the same time as the success, and groups by user AND IP.
SELECT s.event_id AS success_event, s.event_time AS success_time,
       s.user_name, s.source_ip, COUNT(f.event_id) AS preceding_failures,
       COALESCE(a.hostname, 'not in supplied inventory') AS asset
FROM login_events AS s
JOIN login_events AS f ON f.user_name = s.user_name
 AND f.source_ip = s.source_ip AND f.result = 'failure'
 AND julianday(f.event_time) >= julianday(s.event_time) - (10.0 / 1440)
 AND julianday(f.event_time) < julianday(s.event_time)
LEFT JOIN assets AS a ON a.source_ip = s.source_ip
WHERE s.result = 'success'
GROUP BY s.event_id, s.event_time, s.user_name, s.source_ip, a.hostname
HAVING COUNT(f.event_id) >= 3
ORDER BY s.event_time, s.event_id;
