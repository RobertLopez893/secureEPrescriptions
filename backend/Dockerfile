# ==========================================
# 1. ETAPA BASE
# ==========================================
FROM python:3.12-slim AS base
WORKDIR /app

# Solo copiamos e instalamos dependencias primero (para aprovechar el caché)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ==========================================
# 2. ETAPA DE DESARROLLO (Dev)
# ==========================================
FROM base AS development
# En desarrollo NO hacemos COPY . . porque usaremos el VOLUMEN del docker-compose
# Esto garantiza que FastAPI mire tu carpeta real de Windows/Linux
CMD ["uvicorn", "src.api_gateway.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ==========================================
# 3. ETAPA DE PRODUCCIÓN (Prod)
# ==========================================
FROM base AS production
# En producción SÍ copiamos el código, porque ahí no hay volúmenes
COPY . .
CMD ["uvicorn", "src.api_gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]