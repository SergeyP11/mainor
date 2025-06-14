FROM python:3.9-slim

# Создаем непривилегированного пользователя myuser с домашней директорией
RUN useradd -m myuser

# Устанавливаем curl
RUN apt update && apt install -y curl && rm -rf /var/lib/apt/lists/*

# Устанавливаем рабочую директорию и меняем её владельца
WORKDIR /app
RUN chown myuser:myuser /app

# Копируем файл зависимостей
COPY --chown=myuser:myuser requirements.txt .

# Устанавливаем зависимости Python
RUN pip install --no-cache-dir -r requirements.txt

# Копируем все файлы приложения
COPY --chown=myuser:myuser . .

# Переключаемся на пользователя myuser
USER myuser

# Открываем порт 8080
EXPOSE 8080

# Команда для запуска приложения
CMD ["python", "app.py"]