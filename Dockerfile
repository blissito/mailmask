FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --production
COPY . .
RUN mkdir -p data
EXPOSE 8000
CMD ["npx", "tsx", "main.ts"]
