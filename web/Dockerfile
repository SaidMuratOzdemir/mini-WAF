# ── Stage 1: Build ──────────────────────────────────────────────────
FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci --legacy-peer-deps

COPY . .
RUN npm run build
# Output lives in /app/dist (Vite default)

# ── Stage 2: Production Nginx ──────────────────────────────────────
FROM nginx:1.27-alpine

# Remove the default site so our config is the only one
RUN rm -f /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/conf.d/waf-web.conf

# Vite builds into dist/ with asset refs prefixed by base=/admin-ui/.
# Place the build output under /usr/share/nginx/html/admin-ui/ so paths match.
COPY --from=build /app/dist /usr/share/nginx/html/admin-ui

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
