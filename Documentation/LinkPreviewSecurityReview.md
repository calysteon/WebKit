# Link Preview Static Review Findings

This document summarizes privacy and security concerns identified while statically auditing the WebKit code paths exercised by WKWebView-based link previews (e.g. iMessage / Link Presentation). The review assumes previews run inside an ephemeral `WKWebsiteDataStore` with JavaScript and subresource loading intentionally constrained, and focuses on areas where the current implementation may allow credential leakage, state persistence, or policy bypasses.

## 1. Ephemeral Website Data Store configuration

* **Server preconnect is enabled by default.** `WebsiteDataStoreConfiguration` leaves `m_allowsServerPreconnect` defaulted to `true`, and `WebsiteDataStore::parameters()` forwards this to the NetworkProcess for every session, including ephemeral ones.【F:Source/WebKit/UIProcess/WebsiteData/WebsiteDataStoreConfiguration.h†L224-L225】【F:Source/WebKit/UIProcess/WebsiteData/WebsiteDataStoreConfiguration.h†L333-L335】【F:Source/WebKit/UIProcess/WebsiteData/WebsiteDataStore.cpp†L2149-L2155】 This allows the NetworkProcess to reuse speculative connection logic (`NetworkConnectionToWebProcess::preconnectTo`) even when previews are meant to avoid observable preflight traffic.【F:Source/WebKit/NetworkProcess/NetworkConnectionToWebProcess.cpp†L722-L733】  
  **Risk:** Preconnect requests are generated before user intent and can carry identifying information (client IP, TLS SNI, optional proxy-auth headers). For a messaging preview this leaks interest in third-party URLs even if the actual preview later aborts.  
  **Recommendation:** Force `allowsServerPreconnect = false` when the UIProcess instantiates ephemeral preview data stores, or override `WebPageProxy::preconnectTo` to early-return for preview processes.

* **Credential storage remains enabled.** Preview pages inherit `WebPageProxy::m_canUseCredentialStorage`, which defaults to `true`, allowing speculative network requests (preconnect, preloads, pings) to consult shared credential stores when `allowsServerPreconnect()` is left on.【F:Source/WebKit/UIProcess/WebPageProxy.cpp†L6785-L6803】  
  **Recommendation:** Explicitly call `_setCanUseCredentialStorage:NO` on preview `WKWebView` instances and plumb the flag through the `PageConfiguration` used by link previews.

## 2. Speculative networking (preconnect / preload / prefetch)

Even if previews try to block subresource execution, the parser still processes `<link>` hints exposed by remote markup.

* **Preconnect can send credentials cross-origin.** `LinkLoader::preconnectIfNeeded` unconditionally sets `StoredCredentialsPolicy::Use` unless the markup explicitly provides `crossorigin="anonymous"`, and then dispatches to the platform loader strategy.【F:Source/WebCore/loader/LinkLoader.cpp†L300-L321】 In a preview, this lets third-party pages trigger credentialed connection attempts before the user opts in.  
  **Recommendation:** When running in preview mode, disable `linkPreconnectEnabled` in the page settings, or force `storageCredentialsPolicy = StoredCredentialsPolicy::DoNotUse` regardless of markup. A regression test should load HTML containing `<link rel="preconnect" href="https://tracker.example">` inside the preview harness and assert that no outbound connection is attempted.

* **Link preloads honor author credentials.** During `<link rel="preload">` processing, `LinkLoader` copies author-controlled `crossorigin` attributes into `FetchOptions::credentials`, defaulting to `SameOrigin` but upgrading to `Include` for `use-credentials` hints.【F:Source/WebCore/loader/LinkLoader.cpp†L370-L404】 Preview fetches should not let untrusted pages dictate credential use for speculative subresources.  
  **Recommendation:** Gate `preloadIfNeeded` behind a preview-aware setting. Add a LayoutTest that loads malicious markup in preview mode and verifies no subresource requests fire.

* **Link prefetch uses the navigation cache.** `LinkLoader::prefetchIfNeeded` still queues navigational prefetches with `FetchOptions::Mode::Navigate` and `Credentials::SameOrigin`, relying only on the embedder to have disabled the feature via `linkPrefetchEnabled`.【F:Source/WebCore/loader/LinkLoader.cpp†L405-L434】 Preview sessions should ensure that setting is forcibly `false`.

## 3. Anchor ping behaviour

* **Ping requests may use credential storage.** After navigation, `HTMLAnchorElement::sendPings` is invoked and `PingLoader::startPingLoad` determines whether to include credentials by calling `shouldUseCredentialStorage` on the frame loader client.【F:Source/WebCore/html/HTMLAnchorElement.cpp†L595-L601】【F:Source/WebCore/loader/PingLoader.cpp†L223-L266】 In preview contexts, we generally do not want any `ping` traffic, and certainly not with shared credentials.  
  **Recommendation:** Override the frame loader client used by previews so `shouldUseCredentialStorage` returns `false`, and ideally disable pings entirely via `hyperlinkAuditingEnabled = false`. A regression test should exercise an HTML `<a ping>` inside the preview and confirm no network request is emitted.

## 4. Mitigation proposals & testing

* **Configuration hook:** Ensure the ephemeral preview data store builder explicitly sets: `allowsServerPreconnect = false`, `linkPreconnectEnabled = false`, `linkPreloadEnabled = false`, `linkPrefetchEnabled = false`, `hyperlinkAuditingEnabled = false`, and `canUseCredentialStorage = false` before loading any content.
* **Network harness test:** Add a WebKit API test that spins up a preview-mode `WKWebView`, serves HTML containing `<link rel=preconnect>`, `<link rel=prefetch>`, and `<a ping>`, and asserts through a custom protocol handler that no speculative requests occur.
* **Manual verification:** Inspect CFNetwork logs while generating a preview of adversarial markup to ensure there are zero preconnect/ping entries.

Addressing these issues will better align link previews with the expected privacy invariants: no speculative or credentialed third-party traffic, and no side effects that outlive the ephemeral session.
