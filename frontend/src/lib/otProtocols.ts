import type { OtProtocol } from '../api/types';

export interface OtProtocolOption {
  value: OtProtocol;
  label: string;
  defaultPort: number;
}

export const OT_PROTOCOLS: OtProtocolOption[] = [
  { value: 'MODBUS_TCP', label: 'Modbus/TCP', defaultPort: 502 },
  { value: 'DNP3', label: 'DNP3', defaultPort: 20000 },
  { value: 'S7COMM', label: 'S7comm', defaultPort: 102 },
  { value: 'BACNET_IP', label: 'BACnet/IP', defaultPort: 47808 },
];
