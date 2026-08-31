/**
 * Exit values are part of the public CLI contract. Keep this list deliberately
 * small: callers use the values to distinguish a report outcome from an
 * invocation or implementation failure.
 */
import { EXIT_CODES as CONTRACT_EXIT_CODES } from "../contracts/constants.js";

export const EXIT_CODES = Object.freeze({
  SUCCESS: CONTRACT_EXIT_CODES.OK,
  INACTIVE: CONTRACT_EXIT_CODES.COHERENT_BUT_INACTIVE,
  CONTRADICTORY: CONTRACT_EXIT_CODES.CONTRADICTORY,
  INDETERMINATE: CONTRACT_EXIT_CODES.INDETERMINATE,
  USAGE: CONTRACT_EXIT_CODES.USAGE_ERROR,
  INTERNAL: CONTRACT_EXIT_CODES.INTERNAL_ERROR,
} as const);

export type CliExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];
