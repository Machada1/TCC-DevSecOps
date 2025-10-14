# Imagem base leve
FROM python:3.11-slim

# Define o diretório de trabalho
WORKDIR /app

# Copia os arquivos necessários
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Expõe a porta 8080
EXPOSE 8080

# Comando de inicialização
CMD ["python", "main.py"]
