/// <reference types="vite/client" />

/** 构建时注入：工作区 `Cargo.toml` 的 `[workspace.package].version`（见 `vite.config.ts`）。 */
declare const __GATEWAY_VERSION__: string;
