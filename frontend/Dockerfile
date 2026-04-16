# ==========================================
# 1. ETAPA BASE (Instalación de dependencias)
# ==========================================
FROM node:22-alpine AS base

WORKDIR /app
# Solo copiamos los archivos de paquetes para instalar librerías
COPY package*.json ./
RUN npm install

# ==========================================
# 2. ETAPA DE DESARROLLO (Dev)
# ==========================================
FROM base AS development
# IMPORTANTE: NO hacemos "COPY . ." aquí.
# El docker-compose se encargará de montar tu carpeta local en /app
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# ==========================================
# 3. ETAPA DE CONSTRUCCIÓN (Solo para prod)
# ==========================================
FROM base AS builder
# Aquí SÍ necesitamos los archivos para poder compilar
COPY . .
RUN npm run build

# ==========================================
# 4. ETAPA DE PRODUCCIÓN (Prod)
# ==========================================
FROM nginx:alpine AS production
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]