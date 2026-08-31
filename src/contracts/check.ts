import { z } from "zod";

import {
  CHECK_AUTHORITY_VALUES,
  CHECK_VARIANTS,
  CHECK_IDS,
  CHECK_STATE_VALUES,
  REASON_CODES,
  VERIFICATION_METHOD_VALUES,
} from "./constants.js";

export const CheckIdSchema = z.enum(CHECK_IDS);
export const CheckStateSchema = z.enum(CHECK_STATE_VALUES);
export const VerificationMethodSchema = z.enum(VERIFICATION_METHOD_VALUES);
export const CheckAuthoritySchema = z.enum(CHECK_AUTHORITY_VALUES);
export const ReasonCodeSchema = z.enum(REASON_CODES);

/**
 * One deterministic finding in the canonical report.  A check is not valid
 * unless it states what happened, how it was established, which authority it
 * relies on, and a stable code that automation can branch on.
 */
export const CheckSchema = z
  .strictObject({
    id: CheckIdSchema,
    state: CheckStateSchema,
    reason_code: ReasonCodeSchema,
    verification_method: VerificationMethodSchema,
    authority: CheckAuthoritySchema,
    required: z.boolean(),
  })
  .superRefine((check, context) => {
    const matchesCanonicalVariant = CHECK_VARIANTS[check.id].some(
      (variant) =>
        variant.state === check.state &&
        variant.reason_code === check.reason_code &&
        variant.verification_method === check.verification_method &&
        variant.authority === check.authority &&
        variant.required === check.required,
    );
    if (!matchesCanonicalVariant) {
      context.addIssue({
        code: "custom",
        path: [],
        message: `${check.id} has an invalid canonical state/reason/method/authority/required tuple`,
      });
    }
  })
  .meta({
    id: "myproof.par.public-record-check.v1",
    title: "MyProof PAR public-record verification check",
    description:
      "A finite, non-prose finding. Remote evidence and free-form details are never serialized.",
  });

export type CheckId = z.infer<typeof CheckIdSchema>;
export type CheckState = z.infer<typeof CheckStateSchema>;
export type VerificationMethod = z.infer<typeof VerificationMethodSchema>;
export type CheckAuthority = z.infer<typeof CheckAuthoritySchema>;
export type ReasonCode = z.infer<typeof ReasonCodeSchema>;
export type Check = z.infer<typeof CheckSchema>;
