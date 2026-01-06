# TODO - Production Readiness

## Core x64dbg integration (Phase 1 - complete)
- [x] Implement a real transport (TCP, named pipe, or plugin bridge).
- [x] Define a stable command protocol and response schema.
- [x] Add connection lifecycle (connect, reconnect, disconnect, shutdown).
- [x] Add timeouts, retries, and backoff for transient failures.
- [x] Add tool coverage for common debugger actions (attach, detach, pause, step, read/write memory, list modules/threads/regs, set breakpoints).

## MCP server behavior (Phase 2 - complete)
- [x] Add structured error handling and map x64dbg errors to MCP tool errors.
- [x] Validate tool inputs with explicit schemas and ranges.
- [x] Add tool result types and normalize outputs for consistent client use.
- [x] Add optional resources/prompts if you want richer MCP features.

## Config and security
- [x] Support config via env + config file (host, port, transport, timeouts).
- [x] Add allowlist/denylist for target processes if needed.
- [x] Document security posture and expected permissions.

## Observability
- [x] Add structured logging with log levels and redaction.
- [x] Add tracing hooks or debug logs for protocol traffic.
- [x] Add basic metrics (connect failures, command latency).

## Event streaming
- [x] Stream debug events from the x64dbg bridge.
- [x] Add MCP tools for subscribing/polling events.
- [x] Document event configuration.

## Testing
- [x] Add unit tests for protocol parsing and tool handlers.
- [x] Add integration tests with a mocked x64dbg bridge.
- [x] Add smoke tests for server startup and tool listing.

## Packaging and delivery
- [x] Add build output to `dist/` and verify `npm run build` works.
- [x] Add CI (lint, typecheck, tests).
- [x] Add release notes and versioning strategy.
- [x] Provide example MCP client config for common hosts.

## Documentation
- [x] Expand README with setup, troubleshooting, and usage examples.
- [x] Document transport setup steps and required x64dbg plugin configuration.
