FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json pnpm-workspace.yaml ./
COPY apps/backend/package.json ./apps/backend/
COPY packages ./packages
RUN npm i -g pnpm
RUN pnpm install --filter backend...
COPY apps/backend ./apps/backend
WORKDIR /app/apps/backend
RUN pnpm build

FROM node:20-alpine AS runtime
WORKDIR /app
RUN npm i -g pnpm
COPY --from=builder /app/apps/backend/node_modules ./node_modules
COPY --from=builder /app/apps/backend/dist ./dist
COPY --from=builder /app/apps/backend/package.json ./
EXPOSE 3001
CMD ["pnpm","start:prod"]
