// Names for the generated schema types of `crates/rsim-api/openapi.json`.
import type { components } from "./schema";

type S = components["schemas"];

export type PathAnswer = S["PathAnswerOut"];
export type SetAnswer = S["SetAnswerOut"];
export type Answer = S["AnswerJson"];
export type Branch = S["BranchJson"];
export type Reply = S["ReplyJson"];
export type TraceStep = S["TraceStepJson"];
export type PacketSet = S["PacketSetJson"];
export type Header = S["HeaderJson"];
export type Verdict = S["VerdictJson"];
export type Span = S["SpanJson"];
export type SourceText = S["SourceTextJson"];
export type Qos = S["QosJson"];
export type Twin = S["TwinJson"];
export type QueryEcho = S["QueryEcho"];
export type SetEcho = S["SetEcho"];
export type PathQueryArgs = S["PathQueryArgs"];
export type SetQueryArgs = S["SetQueryArgs"];
export type Problem = S["Problem"];
export type TablesOut = S["TablesOut"];
export type TableDef = S["TableDef"];
export type Column = S["Column"];
export type ColumnType = S["ColumnType"];
export type TableOut = S["TableOut"];
export type SummarizeOut = S["SummarizeOut"];
export type UniqueOut = S["UniqueOut"];

/** One header field value of the JSON output. */
export type FieldValue =
  | { known: string | number }
  | { in: unknown[] }
  | "unknown"
  | "absent"
  | "original";
export type Me = S["MeOut"];
export type SetupState = S["SetupOut"];
export type TokenInfo = S["TokenInfo"];
export type TokenIn = S["TokenIn"];
export type NewToken = S["NewTokenOut"];
