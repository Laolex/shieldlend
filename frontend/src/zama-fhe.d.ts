declare module '@zama-fhe/relayer-sdk/web.js' {
  export function initSDK(params?: { tfheParams?: any; kmsParams?: any; thread?: number }): Promise<boolean>;
  export function createInstance(config: any): Promise<any>;
  export const SepoliaConfig: any;
}
