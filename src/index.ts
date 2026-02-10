export { ScannerRegistry } from './scanner-registry';
export { SupplyChainScanner } from './scanners/supply-chain-scanner';
export { walkFiles } from './utils/file-walker';
export * from './types';

import { ScannerRegistry } from './scanner-registry';
import { SupplyChainScanner } from './scanners/supply-chain-scanner';

export function createDefaultRegistry(externalIOCPath?: string): ScannerRegistry {
  const registry = new ScannerRegistry();
  registry.register(new SupplyChainScanner(externalIOCPath));
  return registry;
}
