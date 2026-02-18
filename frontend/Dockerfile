# Build stage
FROM oven/bun:1.3 AS builder

WORKDIR /app

# Copy package files
COPY package.json bun.lock ./

# Install dependencies (not frozen to handle minor version differences)
RUN bun install

# Copy source
COPY . .

# Build
ENV NEXT_TELEMETRY_DISABLED=1
RUN bun run build

# Production stage
FROM oven/bun:1.3-slim AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Create non-root user (bun image is distroless-like, use numeric IDs)
RUN echo "nextjs:x:1001:1001::/app:/sbin/nologin" >> /etc/passwd && \
    echo "nodejs:x:1001:" >> /etc/group || true

# Copy built assets
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["bun", "server.js"]
