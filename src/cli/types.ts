import type { PublicRecordCoherenceReport, VerifyProofAssetRecord } from "../contracts/index.js";

/** The adapters consume the one report type owned by the shared contract. */
export type CanonicalReport = PublicRecordCoherenceReport;
export type VerifyAsset = VerifyProofAssetRecord;

export type RunMcp = (signal?: AbortSignal) => Promise<void>;

export interface CliDependencies {
  readonly verifyProofAssetRecord: VerifyAsset;
  readonly runMcp: RunMcp;
}

export interface OutputSink {
  write(chunk: string): void;
}

export interface CliStreams {
  readonly stdout: OutputSink;
  readonly stderr: OutputSink;
}
