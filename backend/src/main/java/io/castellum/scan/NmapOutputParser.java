package io.castellum.scan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Pure-function parser for nmap's XML output ({@code -oX -}).
 *
 * <p>Parses the {@code <nmaprun>} document produced by nmap and extracts discovered
 * hosts and open services. Uses the JDK's built-in JAXP DOM — no third-party XML
 * dependency. Malformed or unexpected XML is handled defensively: an unparseable
 * document yields an empty result rather than throwing.
 *
 * <p>For services it captures the nmap service {@code name}, {@code product}, the
 * raw {@code version} banner, and the first application CPE ({@code cpe:/a:...}),
 * converted to a CPE 2.3 formatted string. OS CPEs ({@code cpe:/o:...}) are ignored
 * for service correlation but are captured verbatim in the host OS match record.
 *
 * <p>No Spring dependencies are invoked; no repositories are touched. This class is
 * used exclusively by {@code ScanExecutionService}.
 */
@Component
public class NmapOutputParser {

    private static final Logger log = LoggerFactory.getLogger(NmapOutputParser.class);

    // -----------------------------------------------------------------------
    // Output record types (local to this class; ScanExecutionService maps them
    // to Discovery / NetworkService domain objects).
    // -----------------------------------------------------------------------

    /** OS identification result from nmap {@code <os><osmatch>} elements. */
    public record OsMatch(String name, Integer accuracy, String cpe) {}

    /** A discovered host from nmap output. */
    public record DiscoveredHost(String ipAddress, String hostname, OsMatch os) {}

    /**
     * A discovered open port/service from nmap output.
     *
     * @param product the nmap-reported product (may be {@code null})
     * @param cpe23   the application CPE in CPE 2.3 formatted-string form (may be {@code null})
     */
    public record DiscoveredService(String ipAddress, int port, String protocol, String name,
                                    String version, String product, String cpe23) {}

    /** Parser result container. */
    public record ParsedScan(List<DiscoveredHost> hosts, List<DiscoveredService> services) {}

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Parse nmap XML stdout into discovered hosts and services.
     *
     * <p>A host is included when its {@code <status state="up"/>}. Only ports whose
     * {@code <state state="open"/>} contribute services. IPv4 addresses
     * ({@code addrtype="ipv4"}) are preferred as the host address; IPv6-only hosts
     * fall back to their {@code addrtype="ipv6"} address.
     *
     * @param stdout raw stdout string from {@link NmapResult#stdout()} (nmap {@code -oX -})
     * @param type   the scan type (informational; XML shape drives parsing)
     * @return parsed result; never null; empty lists when no hosts found
     */
    public ParsedScan parse(String stdout, ScanType type) {
        List<DiscoveredHost> hosts = new ArrayList<>();
        List<DiscoveredService> services = new ArrayList<>();

        if (stdout == null || stdout.isBlank()) {
            return new ParsedScan(hosts, services);
        }

        Document doc;
        try {
            doc = parseDocument(stdout);
        } catch (Exception e) {
            // Defensive: nmap output that is not valid XML (e.g. an error banner on stderr
            // mistakenly fed here, or a truncated stream) must not crash the scan.
            log.warn("nmap XML parse failed ({}): {}", type, e.getMessage());
            return new ParsedScan(hosts, services);
        }

        NodeList hostNodes = doc.getElementsByTagName("host");
        for (int i = 0; i < hostNodes.getLength(); i++) {
            Element host = (Element) hostNodes.item(i);

            if (!isUp(host)) {
                continue;
            }

            String ip = hostAddress(host);
            if (ip == null) {
                continue; // no IP address — cannot key a device
            }
            String hostname = firstHostname(host);

            hosts.add(new DiscoveredHost(ip, hostname, osMatch(host)));

            for (Element port : openPorts(host)) {
                DiscoveredService svc = toService(ip, port);
                if (svc != null) {
                    services.add(svc);
                }
            }
        }

        return new ParsedScan(hosts, services);
    }

    // -----------------------------------------------------------------------
    // OS fingerprint helpers
    // -----------------------------------------------------------------------

    /**
     * Extract the best OS match from a {@code <host>} element's {@code <os><osmatch>} children.
     * Nmap orders {@code <osmatch>} elements highest-accuracy-first, so we take the first one.
     */
    private static OsMatch osMatch(Element host) {
        Element os = firstChildElement(host, "os");
        if (os == null) {
            return null;
        }
        NodeList matches = os.getElementsByTagName("osmatch");
        if (matches.getLength() == 0) {
            return null;
        }
        // Nmap emits <osmatch> elements highest-accuracy-first — take the first.
        Element osmatch = (Element) matches.item(0);

        String name = emptyToNull(osmatch.getAttribute("name"));

        Integer accuracy;
        try {
            String accStr = osmatch.getAttribute("accuracy");
            accuracy = (accStr == null || accStr.isEmpty()) ? null : Integer.parseInt(accStr);
        } catch (NumberFormatException e) {
            accuracy = null;
        }

        // Prefer the cpe attribute on the first <osclass> child; else look for a <cpe> text node.
        String cpe = null;
        Element osclass = firstChildElement(osmatch, "osclass");
        if (osclass != null) {
            String attr = osclass.getAttribute("cpe");
            if (attr != null && attr.startsWith("cpe:/o:")) {
                cpe = emptyToNull(attr);
            }
        }
        if (cpe == null) {
            NodeList cpeNodes = osmatch.getElementsByTagName("cpe");
            for (int i = 0; i < cpeNodes.getLength(); i++) {
                String val = cpeNodes.item(i).getTextContent();
                if (val != null) {
                    val = val.trim();
                    if (val.startsWith("cpe:/o:")) {
                        cpe = emptyToNull(val);
                        break;
                    }
                }
            }
        }

        return new OsMatch(name, accuracy, cpe);
    }

    // -----------------------------------------------------------------------
    // XML helpers
    // -----------------------------------------------------------------------

    /** Parse a string into a DOM document with an XXE-hardened factory. */
    private static Document parseDocument(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // nmap emits a <!DOCTYPE nmaprun> declaration; disable external entity resolution
        // (XXE hardening) while still tolerating the internal doctype.
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setExpandEntityReferences(false);
        factory.setNamespaceAware(false);
        factory.setXIncludeAware(false);
        try {
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (IllegalArgumentException ignored) {
            // Attribute unsupported by the active parser — features above already cover it.
        }
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputSource src = new InputSource(new StringReader(xml));
        src.setEncoding(StandardCharsets.UTF_8.name());
        return builder.parse(src);
    }

    /** True when the host's {@code <status>} child reports {@code state="up"}. */
    private static boolean isUp(Element host) {
        Element status = firstChildElement(host, "status");
        return status != null && "up".equals(status.getAttribute("state"));
    }

    /**
     * Host address used as the device key: the first {@code <address>} child with
     * {@code addrtype="ipv4"}, falling back to the first {@code addrtype="ipv6"} for
     * IPv6-only hosts. Null when the host has no IP address at all (e.g. MAC only).
     */
    private static String hostAddress(Element host) {
        String ipv4 = addressOfType(host, "ipv4");
        return ipv4 != null ? ipv4 : addressOfType(host, "ipv6");
    }

    /** First {@code <address>} child with the given {@code addrtype}, or null. */
    private static String addressOfType(Element host, String addrtype) {
        NodeList addresses = host.getElementsByTagName("address");
        for (int i = 0; i < addresses.getLength(); i++) {
            Element addr = (Element) addresses.item(i);
            if (addrtype.equals(addr.getAttribute("addrtype"))) {
                String value = addr.getAttribute("addr");
                return value.isEmpty() ? null : value;
            }
        }
        return null;
    }

    /** First {@code <hostname name="...">}, or null when none present. */
    private static String firstHostname(Element host) {
        NodeList names = host.getElementsByTagName("hostname");
        for (int i = 0; i < names.getLength(); i++) {
            Element hostname = (Element) names.item(i);
            String value = hostname.getAttribute("name");
            if (!value.isEmpty()) {
                return value;
            }
        }
        return null;
    }

    /** All {@code <port>} elements whose {@code <state state="open"/>}. */
    private static List<Element> openPorts(Element host) {
        List<Element> result = new ArrayList<>();
        NodeList ports = host.getElementsByTagName("port");
        for (int i = 0; i < ports.getLength(); i++) {
            Element port = (Element) ports.item(i);
            Element state = firstChildElement(port, "state");
            if (state != null && "open".equals(state.getAttribute("state"))) {
                result.add(port);
            }
        }
        return result;
    }

    /** Build a {@link DiscoveredService} from a {@code <port>} element, or null if unusable. */
    private static DiscoveredService toService(String ip, Element port) {
        String protocol = port.getAttribute("protocol");
        if (protocol.isEmpty()) {
            protocol = "tcp"; // sensible default; nmap always emits this in practice
        }
        int portId;
        try {
            portId = Integer.parseInt(port.getAttribute("portid"));
        } catch (NumberFormatException e) {
            return null; // malformed port — skip
        }

        Element service = firstChildElement(port, "service");
        String name = service != null ? emptyToNull(service.getAttribute("name")) : null;
        String product = service != null ? emptyToNull(service.getAttribute("product")) : null;
        // Keep nmap's version string verbatim (may be empty/null); do not normalise here.
        String version = service != null ? service.getAttribute("version") : "";
        String cpe23 = service != null ? applicationCpe23(service) : null;

        return new DiscoveredService(ip, portId, protocol, name, version, product, cpe23);
    }

    /**
     * Find the first {@code <cpe>} child of {@code <service>} that begins with
     * {@code cpe:/a:} (an application CPE) and convert it to a CPE 2.3 formatted
     * string. OS CPEs ({@code cpe:/o:...}) are ignored. Returns null when no
     * application CPE is present.
     */
    private static String applicationCpe23(Element service) {
        NodeList cpes = service.getElementsByTagName("cpe");
        for (int i = 0; i < cpes.getLength(); i++) {
            String value = cpes.item(i).getTextContent();
            if (value != null) {
                value = value.trim();
                if (value.startsWith("cpe:/a:")) {
                    return convertCpe22ToCpe23(value);
                }
            }
        }
        return null;
    }

    /**
     * Convert an nmap CPE-2.2 URI ({@code cpe:/a:vendor:product[:version[:...]]}) to a
     * CPE 2.3 formatted string ({@code cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*}).
     * Missing trailing components are padded with {@code *}; an absent version yields {@code *}.
     */
    private static String convertCpe22ToCpe23(String cpe22) {
        // Strip the "cpe:/" scheme prefix, then split the remaining colon-separated fields.
        String body = cpe22.substring("cpe:/".length());
        String[] parts = body.split(":", -1);

        // CPE 2.3 formatted string has 11 components after "cpe:2.3:": part, vendor, product,
        // version, update, edition, language, sw_edition, target_sw, target_hw, other.
        String[] out = new String[11];
        for (int i = 0; i < out.length; i++) {
            String value = (i < parts.length) ? parts[i].trim() : "";
            out[i] = value.isEmpty() ? "*" : value;
        }

        StringBuilder sb = new StringBuilder("cpe:2.3");
        for (String field : out) {
            sb.append(':').append(field);
        }
        return sb.toString();
    }

    /** First direct child element with the given tag name, or null. */
    private static Element firstChildElement(Element parent, String tagName) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE && tagName.equals(node.getNodeName())) {
                return (Element) node;
            }
        }
        return null;
    }

    private static String emptyToNull(String value) {
        return (value == null || value.isEmpty()) ? null : value;
    }
}
