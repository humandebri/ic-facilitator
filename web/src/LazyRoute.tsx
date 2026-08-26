import { Component, Suspense, type ErrorInfo, type ReactNode } from "react";

type BoundaryState = { failed: boolean };

class RouteErrorBoundary extends Component<{ children: ReactNode }, BoundaryState> {
  state: BoundaryState = { failed: false };

  static getDerivedStateFromError(): BoundaryState {
    return { failed: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    if (import.meta.env.DEV) console.error("route chunk failed to load", error, info.componentStack);
  }

  render(): ReactNode {
    if (this.state.failed) {
      return <section className="page route-fallback" role="alert"><p className="eyebrow">LOAD ERROR</p><h1>ページを読み込めませんでした</h1><p>通信状態を確認して、もう一度読み込んでください。</p><button className="button" autoFocus onClick={() => window.location.reload()}>再読み込み</button></section>;
    }
    return this.props.children;
  }
}

function RouteLoading() {
  return <section className="page route-fallback" role="status" aria-live="polite" aria-busy="true" tabIndex={0}><p className="eyebrow">LOADING</p><h1>ページを読み込んでいます</h1><div className="loading-bar" aria-hidden="true"><span /></div></section>;
}

export function LazyRoute({ children }: { children: ReactNode }) {
  return <RouteErrorBoundary><Suspense fallback={<RouteLoading />}>{children}</Suspense></RouteErrorBoundary>;
}
