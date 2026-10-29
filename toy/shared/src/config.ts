// Local endpoints for the toy stack. Override with environment variables.
export const config = {
  plcUrl: process.env.ATSIG_PLC_URL ?? 'http://localhost:2582',
  pdsUrl: process.env.ATSIG_PDS_URL ?? 'http://localhost:3000',
  relayUrl: process.env.ATSIG_RELAY_URL ?? 'ws://localhost:2470',
  appviewUrl: process.env.ATSIG_APPVIEW_URL ?? 'http://localhost:4000',
}
