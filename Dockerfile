# Stage 1: builder
FROM node:18-alpine AS builder
WORKDIR /build
RUN apk add --no-cache python3 make g++
COPY package*.json ./
RUN npm ci
COPY . .
RUN node src/keygen.js || true
FROM node:18-alpine
ENV NODE_ENV=production TZ=UTC
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY --from=builder /build/src ./src
COPY --from=builder /build/keys ./keys
COPY --from=builder /build/cron ./cron
COPY --from=builder /build/entrypoint.sh ./entrypoint.sh
RUN mkdir -p /data /cron && chown -R node:node /data /cron /app
RUN apk add --no-cache tzdata
RUN chmod +x /app/entrypoint.sh
EXPOSE 8080
USER node
ENTRYPOINT ["/app/entrypoint.sh"]

