/**
 * Sentori Runtime ToolCallInterceptor
 * Wraps a tool object with a Proxy to emit events before/after each tool call.
 */

import { EventEmitter } from 'events';
import { randomUUID } from 'crypto';
import type { ToolCallEvent, RuntimeEvent } from './event-schema';

export class ToolCallInterceptor {
  private emitter: EventEmitter;

  constructor() {
    this.emitter = new EventEmitter();
    // Avoid unhandled-listener warnings in large deployments
    this.emitter.setMaxListeners(50);
  }

  /**
   * Wrap a tools object so every property function is intercepted.
   * Returns a Proxy of the same type T.
   */
  wrap<T extends Record<string, (...args: unknown[]) => unknown>>(tools: T): T {
    const self = this;

    return new Proxy(tools, {
      get(target, prop: string | symbol, receiver) {
        const value = Reflect.get(target, prop, receiver);

        // Only intercept functions
        if (typeof value !== 'function') return value;

        return function (...callArgs: unknown[]) {
          const id = randomUUID();
          const toolName = String(prop);
          const timestamp = new Date().toISOString();
          const startMs = Date.now();

          // Build base event (args flattened into record)
          const baseEvent: ToolCallEvent = {
            id,
            timestamp,
            toolName,
            args: callArgs[0] && typeof callArgs[0] === 'object' && !Array.isArray(callArgs[0])
              ? (callArgs[0] as Record<string, unknown>)
              : { _args: callArgs },
          };

          const startRuntimeEvent: RuntimeEvent = {
            type: 'tool_call_start',
            data: { ...baseEvent },
          };
          self.emitter.emit('tool_call_start', startRuntimeEvent);

          let result: unknown;
          try {
            result = value.apply(target, callArgs);
          } catch (err: unknown) {
            const durationMs = Date.now() - startMs;
            const errorEvent: RuntimeEvent = {
              type: 'tool_call_error',
              data: {
                ...baseEvent,
                durationMs,
                error: err instanceof Error ? err.message : String(err),
              },
            };
            self.emitter.emit('tool_call_error', errorEvent);
            throw err;
          }

          // Handle both sync and async (Promise) results
          const finish = (resolvedResult: unknown) => {
            const durationMs = Date.now() - startMs;
            const endRuntimeEvent: RuntimeEvent = {
              type: 'tool_call_end',
              data: { ...baseEvent, result: resolvedResult, durationMs },
            };
            self.emitter.emit('tool_call_end', endRuntimeEvent);
            return resolvedResult;
          };

          const fail = (err: unknown) => {
            const durationMs = Date.now() - startMs;
            const errorEvent: RuntimeEvent = {
              type: 'tool_call_error',
              data: {
                ...baseEvent,
                durationMs,
                error: err instanceof Error ? err.message : String(err),
              },
            };
            self.emitter.emit('tool_call_error', errorEvent);
            return Promise.reject(err);
          };

          if (result instanceof Promise) {
            return result.then(finish, fail);
          }

          return finish(result);
        };
      },
    });
  }

  on(
    event: 'tool_call_start' | 'tool_call_end' | 'tool_call_error',
    handler: (e: RuntimeEvent) => void,
  ): void {
    this.emitter.on(event, handler);
  }

  off(event: string, handler: (...args: unknown[]) => void): void {
    this.emitter.off(event, handler);
  }
}
