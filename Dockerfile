FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src
COPY public ./public
RUN mkdir -p /app/logs /app/data && chown -R node:node /app/logs /app/data
USER node
EXPOSE 3200
# data = settings (encrypted service-account password), logs = audit trail. Keep both on persistent storage.
VOLUME ["/app/data", "/app/logs"]
CMD ["node", "src/server.js"]
