import { app, HttpRequest, HttpResponseInit, InvocationContext } from '@azure/functions';
import {
  CopilotRuntime,
  ExperimentalEmptyAdapter,
  copilotRuntimeNodeHttpEndpoint,
} from '@copilotkit/runtime';
import { IncomingMessage, ServerResponse } from 'http';
import { Readable } from 'stream';

// Initialize service adapter once for better performance
const serviceAdapter = new ExperimentalEmptyAdapter();

/**
 * Azure Function implementation of CopilotKit Runtime
 * Provides the same functionality as the standalone Node.js server
 */
export async function copilotRuntime(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
  // Security: Validate request method
  const allowedMethods = ['GET', 'POST', 'OPTIONS'];
  if (!allowedMethods.includes(request.method?.toUpperCase() || '')) {
    context.log(`Blocked request with invalid method: ${request.method}`);
    return {
      status: 405,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || '*',
      },
      body: JSON.stringify({ error: 'Method not allowed' }),
    };
  }

  // Security: Check content length to prevent DoS
  const maxContentLength = parseInt(process.env.MAX_CONTENT_LENGTH || '10485760'); // 10MB default
  const contentLength = parseInt(request.headers.get('content-length') || '0');
  if (contentLength > maxContentLength) {
    context.log(`Blocked request with excessive content length: ${contentLength}`);
    return {
      status: 413,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || '*',
      },
      body: JSON.stringify({ error: 'Request entity too large' }),
    };
  }

  context.log(`CopilotKit Runtime function processing ${request.method} request for: ${request.url}`);

  // Handle CORS preflight requests
  if (request.method === 'OPTIONS') {
    return {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-copilotkit-*',
        'Access-Control-Max-Age': '86400',
        'Vary': 'Origin',
      },
    };
  }

  try {
    // Security: Validate and sanitize remote endpoint URL
    const remoteEndpointUrl = process.env.LANGGRAPH_SERVICE_URL;
    if (!remoteEndpointUrl) {
      context.log('LANGGRAPH_SERVICE_URL not configured');
      return {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || '*',
        },
        body: JSON.stringify({ error: 'Service configuration error' }),
      };
    }

    // Security: Validate URL format
    try {
      new URL(remoteEndpointUrl);
    } catch {
      context.log(`Invalid LANGGRAPH_SERVICE_URL format: ${remoteEndpointUrl}`);
      return {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || '*',
        },
        body: JSON.stringify({ error: 'Service configuration error' }),
      };
    }

    context.log(`Using remote endpoint: ${remoteEndpointUrl}`);

    // Initialize CopilotRuntime with remote endpoints
    const runtime = new CopilotRuntime({
      remoteEndpoints: [
        { url: remoteEndpointUrl },
      ],
    });

    // Create the CopilotKit handler
    const handler = copilotRuntimeNodeHttpEndpoint({
      endpoint: '/api/copilotkit',
      runtime,
      serviceAdapter,
    });

    // Convert Azure Functions request to Node.js IncomingMessage format
    const requestBody = await request.text();
    const nodeReq = new Readable() as IncomingMessage;
    nodeReq.url = request.url;
    nodeReq.method = request.method;
    nodeReq.headers = Object.fromEntries(request.headers.entries());
    nodeReq.push(requestBody);
    nodeReq.push(null); // End the stream

    // Create response wrapper that captures Node.js ServerResponse behavior
    let responseBody: string = '';
    let responseHeaders: Record<string, string> = {};
    let statusCode = 200;
    let responseEnded = false;

    const nodeRes = {
      writeHead: (code: number, headers?: Record<string, string>) => {
        statusCode = code;
        if (headers) {
          responseHeaders = { ...responseHeaders, ...headers };
        }
      },
      setHeader: (name: string, value: string | string[]) => {
        responseHeaders[name] = Array.isArray(value) ? value.join(', ') : value;
      },
      getHeader: (name: string) => responseHeaders[name],
      write: (data: any) => {
        responseBody += data;
      },
      end: (data?: any) => {
        if (data) {
          responseBody += data;
        }
        responseEnded = true;
      },
      on: () => {}, // Stub for event listeners
      once: () => {}, // Stub for event listeners
      emit: () => {}, // Stub for event emitter
    } as any; // Type assertion needed for compatibility with CopilotKit handler

    // Security: Limit request timeout to prevent resource exhaustion
    const requestTimeout = parseInt(process.env.REQUEST_TIMEOUT_MS || '30000'); // 30 seconds default

    // Execute the CopilotKit handler
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Request timeout'));
      }, requestTimeout);

      try {
        handler(nodeReq, nodeRes as any); // Type assertion needed for mock response object

        // Poll for response completion
        const checkCompletion = () => {
          if (responseEnded) {
            clearTimeout(timeout);
            resolve();
          } else {
            setTimeout(checkCompletion, 10);
          }
        };
        checkCompletion();
      } catch (error) {
        clearTimeout(timeout);
        reject(error);
      }
    });

    // Return Azure Functions response with security headers
    return {
      status: statusCode,
      headers: {
        'Content-Type': responseHeaders['content-type'] || 'application/json',
        'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-copilotkit-*',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Vary': 'Origin',
        ...responseHeaders,
      },
      body: responseBody,
    };
  } catch (error) {
    // Security: Log error but don't expose sensitive information
    context.log('Error in CopilotKit Runtime function:', error);

    const errorMessage = process.env.NODE_ENV === 'development' && error instanceof Error
      ? error.message
      : 'Internal server error';

    return {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || '*',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
      },
      body: JSON.stringify({
        error: 'Internal server error',
        message: errorMessage,
        timestamp: new Date().toISOString(),
      }),
    };
  }
}

// Health check endpoint
export async function healthCheck(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
  context.log('Health check requested');

  // Security: Basic rate limiting check (simple implementation)
  const clientIP = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
  context.log(`Health check from IP: ${clientIP}`);

  const healthData = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    service: 'copilot-runtime-azure-function',
    environment: process.env.NODE_ENV || 'unknown'
  };

  // Security: Don't expose sensitive information in production
  if (process.env.NODE_ENV !== 'production') {
    Object.assign(healthData, {
      nodeVersion: process.version,
      uptime: process.uptime(),
    });
  }

  return {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || '*',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
    },
    body: JSON.stringify(healthData),
  };
}

// Register the health check function
app.http('healthcheck', {
  methods: ['GET'],
  authLevel: 'function',
  handler: healthCheck,
});

// Register the main CopilotKit runtime function
app.http('copilotkit', {
  methods: ['GET', 'POST', 'OPTIONS'],
  authLevel: 'function', // Consider changing to 'function' or 'admin' for production
  handler: copilotRuntime,
});
