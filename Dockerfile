FROM node:18-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
# --ignore-scripts: this repository declares five optional peerDependencies
# (llm-shield, llm-edge-agent, …) that are not installed and must not trigger
# lifecycle scripts during a security-service build.
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:18-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=build /app/dist ./dist
ENV PORT=8080
EXPOSE 8080
CMD ["node", "dist/server.js"]
