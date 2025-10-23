FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json pnpm-workspace.yaml ./
COPY apps/frontend/package.json ./apps/frontend/
COPY packages ./packages
RUN npm i -g pnpm
RUN pnpm install --filter frontend...
COPY apps/frontend ./apps/frontend
WORKDIR /app/apps/frontend
RUN pnpm build

FROM node:20-alpine AS runtime
WORKDIR /app
RUN npm i -g pnpm
COPY --from=builder /app/apps/frontend/.next ./.next
COPY --from=builder /app/apps/frontend/public ./public
COPY --from=builder /app/apps/frontend/package.json ./
EXPOSE 3000
CMD ["pnpm","start"]
