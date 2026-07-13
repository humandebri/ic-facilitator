import { createWalletClient, custom, getAddress, type WalletClient } from "viem";

export type InjectedProvider = { request(args: { method: string; params?: readonly unknown[] }): Promise<unknown> };
export type WalletState = { address: `0x${string}`; client: WalletClient; provider: InjectedProvider };
type ProviderDetail = { info: { name: string; rdns: string; uuid: string }; provider: InjectedProvider };

declare global { interface Window { ethereum?: InjectedProvider } }

async function discoverProvider(): Promise<InjectedProvider | undefined> {
  const providers = await new Promise<ProviderDetail[]>((resolve) => {
    const found = new Map<string, ProviderDetail>();
    const onAnnounce = (event: Event) => {
      const detail = (event as CustomEvent<ProviderDetail>).detail;
      if (detail?.info?.uuid && detail.provider) found.set(detail.info.uuid, detail);
    };
    window.addEventListener("eip6963:announceProvider", onAnnounce);
    window.dispatchEvent(new Event("eip6963:requestProvider"));
    window.setTimeout(() => { window.removeEventListener("eip6963:announceProvider", onAnnounce); resolve([...found.values()]); }, 80);
  });
  return providers.find(item => item.info.rdns.toLowerCase().includes("rabby"))?.provider
    ?? providers.find(item => item.info.rdns.toLowerCase().includes("metamask"))?.provider
    ?? providers[0]?.provider
    ?? window.ethereum;
}

export async function connectWallet(): Promise<WalletState> {
  const provider = await discoverProvider();
  if (!provider) throw new Error("RabbyまたはMetaMaskをインストールしてください。");
  const accounts = await provider.request({ method: "eth_requestAccounts" });
  if (!Array.isArray(accounts) || typeof accounts[0] !== "string") throw new Error("Wallet addressを取得できませんでした。");
  const address = getAddress(accounts[0]);
  return { address, client: createWalletClient({ account: address, transport: custom(provider) }), provider };
}

export async function requireChain(provider: InjectedProvider, chainId: number): Promise<void> {
  const current = await provider.request({ method: "eth_chainId" });
  if (Number(current) !== chainId) throw new Error(`Walletをchain ${chainId}へ切り替えてください。`);
}
