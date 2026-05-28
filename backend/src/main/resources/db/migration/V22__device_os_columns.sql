-- V22: device OS-fingerprint columns
--
-- Populated from nmap -O XML <os><osmatch name=... accuracy=...>. Nullable: most
-- devices are never OS-fingerprinted, and existing rows predate OS parsing
-- (filled on re-scan; last-writer-wins). os_name is the nmap osmatch name;
-- os_accuracy is the 0-100 confidence; os_cpe is the optional raw cpe:/o: OS CPE.
ALTER TABLE device ADD COLUMN os_name VARCHAR(255);
ALTER TABLE device ADD COLUMN os_accuracy INTEGER;
ALTER TABLE device ADD COLUMN os_cpe VARCHAR(255);
