# Stage 1: Build native dependencies
FROM node:18-alpine AS builder

# Install build dependencies for native modules (sqlite3)
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install all dependencies (including dev for building)
RUN npm ci --only=production && \
    npm cache clean --force && \
    # Remove build-time only packages not needed at runtime
    rm -rf node_modules/node-gyp \
           node_modules/@npmcli \
           node_modules/make-fetch-happen \
           node_modules/minipass-fetch \
           node_modules/cacache \
           node_modules/ssri \
           node_modules/unique-filename \
           node_modules/proc-log \
           node_modules/npm-normalize-package-bin \
           node_modules/npm-bundled \
           node_modules/npm-packlist \
           node_modules/ignore-walk \
           node_modules/npm-install-checks \
           node_modules/npmlog \
           node_modules/gauge \
           node_modules/are-we-there-yet \
           node_modules/wide-align \
           node_modules/console-control-strings \
           node_modules/aproba \
           node_modules/has-unicode \
           node_modules/nopt \
           node_modules/abbrev && \
    # Remove unnecessary files from remaining packages
    find node_modules -type f \( \
        -name "*.md" -o \
        -name "*.ts" -o \
        -name "*.map" -o \
        -name "LICENSE*" -o \
        -name "CHANGELOG*" -o \
        -name "HISTORY*" -o \
        -name ".npmignore" -o \
        -name ".eslintrc*" -o \
        -name ".travis.yml" -o \
        -name "Makefile" -o \
        -name "*.gyp" -o \
        -name "binding.gyp" \
    \) -delete 2>/dev/null || true && \
    find node_modules -type d \( \
        -name "test" -o \
        -name "tests" -o \
        -name "docs" -o \
        -name ".github" -o \
        -name "example" -o \
        -name "examples" \
    \) -exec rm -rf {} + 2>/dev/null || true

# Stage 2: Production image
FROM node:18-alpine

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Set working directory
WORKDIR /app

# Copy node_modules from builder (includes compiled native modules)
COPY --from=builder /app/node_modules ./node_modules

# Copy package files
COPY package.json package-lock.json* ./

# Copy the rest of the app
COPY . .

# Make entrypoint executable and create data directory
RUN chmod +x /app/docker-entrypoint.sh && \
    mkdir -p /app/data && \
    chmod 777 /app/data

# Expose the port
EXPOSE 8790

# Set environment variables (override in production as needed)
ENV NODE_ENV=production \
    PORT=8790 \
    DATABASE_PATH=/app/data/wled-presets.sqlite

# Health check (uses PORT env var)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "fetch('http://localhost:' + (process.env.PORT || 8790) + '/api/config/public').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

# Start the server
ENTRYPOINT ["/app/docker-entrypoint.sh"]
