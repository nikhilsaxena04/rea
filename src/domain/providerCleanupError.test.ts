import { expect, it } from "vitest";
import { ProviderCleanupError } from "./providerCleanupError.js";
import { projectAnalysisError } from "./analysisErrorProjection.js";
import { analysisErrorWithCleanupFailure } from "./analysisErrorCleanup.js";
it("preserves the binary cleanup default and an explicitly owned nonbinary operation", () => {
  expect(new ProviderCleanupError("ghidra", ["database"], {}).operation).toBe(
    "close_binary",
  );
  const error = new ProviderCleanupError(
    "source-map-decoder",
    ["runtime"],
    { reason: "cleanup failed" },
    { operation: "trace_web_source_location" },
  );
  expect(error.operation).toBe("trace_web_source_location");
  expect(projectAnalysisError(error)).toMatchObject({
    code: "cleanup_incomplete",
    details: { operation: "trace_web_source_location" },
  });
});

it.each([false, true])(
  "combines only live cleanup resources when primary resolution is %s",
  (resolved) => {
    const primary = new ProviderCleanupError(
      "adb",
      ["publication-handle"],
      { reason: "first descriptor close failed" },
      { operation: "capture_adb_screen" },
    );
    if (resolved) primary.resolveCleanup();
    const cleanup = new ProviderCleanupError("adb", ["runtime-root"], {
      reason: "workspace removal failed",
    });

    const combined = analysisErrorWithCleanupFailure(primary, cleanup);
    expect(projectAnalysisError(combined)).toMatchObject({
      code: "cleanup_incomplete",
      details: {
        resources: resolved
          ? ["runtime-root"]
          : ["publication-handle", "runtime-root"],
        diagnostics: {
          primary_error: {
            details: {
              diagnostics: { reason: "first descriptor close failed" },
            },
          },
          cleanup_error: {
            details: { diagnostics: { reason: "workspace removal failed" } },
          },
        },
      },
    });
    expect(combined.cause).toBeInstanceOf(AggregateError);
    expect((combined.cause as AggregateError).errors).toEqual([
      primary,
      cleanup,
    ]);
  },
);

it("omits released child resources from aggregate live cleanup resources", () => {
  const first = new ProviderCleanupError("provider-alpha", ["alpha-file"], {
    reason: "alpha close failed",
  });
  const second = new ProviderCleanupError("provider-beta", ["beta-file"], {
    reason: "beta close failed",
  });
  const aggregate = new ProviderCleanupError(
    "composite",
    ["alpha-file", "beta-file"],
    {
      reason: "composite close failed",
      historical_resources: ["alpha-file", "beta-file"],
    },
  ).bindCleanupDependencies([first, second]);

  expect(aggregate.cleanupIncomplete).toBe(true);
  expect(aggregate.cleanupResources).toEqual(["alpha-file", "beta-file"]);
  expect(projectAnalysisError(aggregate)).toMatchObject({
    code: "cleanup_incomplete",
    details: {
      resources: ["alpha-file", "beta-file"],
      diagnostics: {
        historical_resources: ["alpha-file", "beta-file"],
      },
    },
  });

  first.resolveCleanup();

  expect(first.cleanupIncomplete).toBe(false);
  expect(first.cleanupResources).toEqual([]);
  expect(aggregate.cleanupIncomplete).toBe(true);
  expect(aggregate.cleanupResources).toEqual(["beta-file"]);
  expect(projectAnalysisError(aggregate)).toMatchObject({
    code: "cleanup_incomplete",
    details: {
      resources: ["beta-file"],
      diagnostics: {
        historical_resources: ["alpha-file", "beta-file"],
      },
    },
  });
});

it("propagates child cleanup resolution through nested aggregates", () => {
  const first = new ProviderCleanupError("provider-alpha", ["alpha-file"], {
    reason: "alpha close failed",
  });
  const second = new ProviderCleanupError("provider-beta", ["beta-file"], {
    reason: "beta close failed",
  });
  const aggregate = new ProviderCleanupError(
    "composite",
    ["alpha-file", "beta-file"],
    { reason: "composite close failed" },
  ).bindCleanupDependencies([first, second]);

  const third = new ProviderCleanupError("provider-gamma", ["third-file"], {
    reason: "gamma close failed",
  });
  const parentAggregate = new ProviderCleanupError(
    "outer-composite",
    ["alpha-file", "beta-file", "third-file"],
    { reason: "outer close failed" },
  ).bindCleanupDependencies([aggregate, third]);

  expect(parentAggregate.cleanupIncomplete).toBe(true);
  expect(parentAggregate.cleanupResources).toEqual([
    "alpha-file",
    "beta-file",
    "third-file",
  ]);

  first.resolveCleanup();

  expect(aggregate.cleanupIncomplete).toBe(true);
  expect(aggregate.cleanupResources).toEqual(["beta-file"]);
  expect(parentAggregate.cleanupIncomplete).toBe(true);
  expect(parentAggregate.cleanupResources).toEqual(["beta-file", "third-file"]);
  expect(projectAnalysisError(parentAggregate)).toMatchObject({
    code: "cleanup_incomplete",
    details: {
      resources: ["beta-file", "third-file"],
    },
  });
});
