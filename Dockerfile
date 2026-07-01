# syntax=docker/dockerfile:1
FROM node:20-alpine AS builder

WORKDIR /app

# Copia apenas os arquivos de dependências primeiro (cache de build)
COPY package*.json ./
COPY tsconfig.json ./

# Instala todas as deps (incluindo devDeps para build)
RUN npm ci

# Copia o código fonte
COPY src/ ./src/

# Compila o TypeScript para JavaScript
RUN npm run build

# ---- Imagem final enxuta ----
FROM node:20-alpine AS runner

WORKDIR /app

# Copia apenas as deps de produção
COPY package*.json ./
RUN npm ci --omit=dev

# Copia o build compilado
COPY --from=builder /app/dist ./dist

# Expõe a porta (Railway injeta PORT automaticamente)
EXPOSE 3000

# Inicia o servidor compilado
CMD ["node", "dist/server.js"]
