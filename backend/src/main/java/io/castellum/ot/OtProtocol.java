package io.castellum.ot;

/**
 * OT/ICS protocols supported by the read-only fingerprinter.
 *
 * <p>Each constant carries the L7 name used in the {@code service.protocol} column
 * and the IANA default port for the protocol.
 */
public enum OtProtocol {
    MODBUS_TCP("modbus", 502),
    DNP3("dnp3", 20000),
    S7COMM("s7comm", 102),
    BACNET_IP("bacnet", 47808);

    private final String l7Name;
    private final int defaultPort;

    OtProtocol(String l7Name, int defaultPort) {
        this.l7Name = l7Name;
        this.defaultPort = defaultPort;
    }

    /** The L7 protocol name used in the {@code service.protocol} column. */
    public String l7Name() { return l7Name; }

    /** IANA default port for this protocol. */
    public int defaultPort() { return defaultPort; }
}
