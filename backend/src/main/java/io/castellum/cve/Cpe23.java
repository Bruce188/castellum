package io.castellum.cve;

public record Cpe23(String part, String vendor, String product, String version, String update,
                    String edition, String language, String swEdition, String targetSw,
                    String targetHw, String other) {

    public static Cpe23 parse(String uri) {
        if (uri == null) throw new IllegalArgumentException("CPE URI is null");
        String[] parts = uri.split(":", -1);
        // Expected: cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<swEdition>:<targetSw>:<targetHw>:<other>
        // That is 13 colon-separated components
        if (parts.length != 13 || !"cpe".equals(parts[0]) || !"2.3".equals(parts[1])) {
            throw new IllegalArgumentException("Malformed CPE 2.3 URI: " + uri);
        }
        return new Cpe23(parts[2], parts[3], parts[4], parts[5], parts[6], parts[7],
                         parts[8], parts[9], parts[10], parts[11], parts[12]);
    }

    public String prefixVendorProduct() {
        return "cpe:2.3:" + part + ":" + vendor + ":" + product + ":";
    }
}
