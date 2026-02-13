# This stage installs dependencies and compiles TypeScript to production JavaScript.
FROM node:20-alpine AS build
WORKDIR /app

# This step copies package metadata first to maximize layer caching.
COPY package.json ./
RUN npm install

# This step copies source files and builds the project.
COPY tsconfig.json eslint.config.js .prettierrc ./
COPY src ./src
RUN npm run build

# This stage creates a minimal runtime image with production dependencies only.
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

# This step installs runtime dependencies only.
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

# This step copies built server artifacts.
COPY --from=build /app/dist ./dist

# This ensures the persistent data directory exists and is writable by the node user.
RUN mkdir -p /data && chown -R node:node /data /app
USER node

# This declares the listening port and volume contract.
EXPOSE 8080
VOLUME ["/data"]

# This runs the MCP server process.
CMD ["node", "dist/index.js"]
