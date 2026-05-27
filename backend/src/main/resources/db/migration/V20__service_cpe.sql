-- V20: service.cpe column
--
-- Stores the application CPE 2.3 formatted string captured from nmap's XML
-- <service><cpe> element (e.g. cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*).
-- Nullable: not every service reports a CPE, and existing rows predate XML parsing.
-- CpeMapper.toCpe23 returns this verbatim when present; otherwise it falls back to
-- the name-based derivation. A CPE 2.3 string maxes out well under 255 chars.

ALTER TABLE service ADD COLUMN cpe VARCHAR(255);
