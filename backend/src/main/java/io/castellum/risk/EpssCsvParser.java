package io.castellum.risk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class EpssCsvParser {
    private static final Logger log = LoggerFactory.getLogger(EpssCsvParser.class);
    private static final String EXPECTED_HEADER = "cve,epss,percentile";
    private static final Pattern SCORE_DATE_PATTERN = Pattern.compile("score_date:(\\d{4}-\\d{2}-\\d{2})");

    private EpssCsvParser() {}

    public record ParseResult(LocalDate scoreDate, List<EpssRow> rows) {}

    public static ParseResult parse(Reader reader) throws IOException {
        BufferedReader br = (reader instanceof BufferedReader b) ? b : new BufferedReader(reader);
        List<EpssRow> rows = new ArrayList<>();
        LocalDate scoreDate = null;
        String line;
        int lineNumber = 0;
        boolean headerSeen = false;
        while ((line = br.readLine()) != null) {
            lineNumber++;
            if (line.startsWith("#")) {
                Matcher m = SCORE_DATE_PATTERN.matcher(line);
                if (m.find()) {
                    scoreDate = LocalDate.parse(m.group(1));
                }
                continue;
            }
            if (!headerSeen) {
                if (!line.trim().equals(EXPECTED_HEADER)) {
                    throw new IllegalArgumentException(
                        "expected EPSS CSV header line '" + EXPECTED_HEADER + "' but got: '" + line + "'");
                }
                headerSeen = true;
                continue;
            }
            String[] parts = line.split(",");
            if (parts.length != 3) {
                log.warn("EPSS CSV line {} skipped (expected 3 fields, got {}): {}", lineNumber, parts.length, line);
                continue;
            }
            try {
                double epss = Double.parseDouble(parts[1].trim());
                double percentile = Double.parseDouble(parts[2].trim());
                rows.add(new EpssRow(parts[0].trim(), epss, percentile));
            } catch (IllegalArgumentException e) {
                log.warn("EPSS CSV line {} skipped: {}", lineNumber, e.getMessage());
            }
        }
        if (scoreDate == null) {
            scoreDate = LocalDate.now(ZoneOffset.UTC);
            log.warn("EPSS CSV had no #score_date comment; defaulting to today UTC: {}", scoreDate);
        }
        return new ParseResult(scoreDate, rows);
    }
}
