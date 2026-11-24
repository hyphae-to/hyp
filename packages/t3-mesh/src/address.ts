// Mesh addresses: `<connector-id>/<handle>` (SPEC.md section 2).

const CONNECTOR_ID = /^[a-z0-9][a-z0-9@._-]{0,63}$/;
const HANDLE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export interface Address {
  readonly connectorId: string;
  readonly handle: string;
}

export const isConnectorId = (value: string): boolean => CONNECTOR_ID.test(value);
export const isHandle = (value: string): boolean => HANDLE.test(value);

export function parseAddress(value: string): Address | null {
  const slash = value.lastIndexOf("/");
  if (slash < 0) return null;
  const connectorId = value.slice(0, slash);
  const handle = value.slice(slash + 1);
  return isConnectorId(connectorId) && isHandle(handle) ? { connectorId, handle } : null;
}

export const formatAddress = (address: Address): string => `${address.connectorId}/${address.handle}`;
