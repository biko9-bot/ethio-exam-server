FROM node:22-slim
WORKDIR /app
COPY . .
ENV NODE_ENV=production
EXPOSE 3000
VOLUME ["/app/data", "/app/uploads"]
CMD ["node", "src/server.js"]
