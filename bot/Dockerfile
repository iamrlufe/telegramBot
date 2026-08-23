# Сборка из корня репозитория: docker compose задаёт context: .
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
COPY bot/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# bot/ и shared/ сливаются в один плоский /app. Раньше shared/ копировался
# последним и молча перекрывал одноимённые файлы: устаревшая копия модуля,
# забытая в shared/, побеждала свежую из bot/ — и это выглядело как
# «код скопирован, а работает старый». Теперь совпадение имён останавливает
# сборку с понятным сообщением вместо тихой перезаписи.
COPY bot/ ./_app_src/
COPY shared/ ./_shared_src/
RUN set -e; \
    dups="$( (ls -1p _app_src | grep -v '/$'; ls -1p _shared_src | grep -v '/$') \
             | sort | uniq -d )"; \
    if [ -n "$dups" ]; then \
        echo "───────────────────────────────────────────────"; \
        echo "СБОРКА ОСТАНОВЛЕНА: одинаковые имена файлов"; \
        echo "в bot/ и shared/:"; \
        echo "$dups"; \
        echo "Оба каталога копируются в /app, поэтому один файл"; \
        echo "молча перекроет другой. Удалите лишнюю копию."; \
        echo "───────────────────────────────────────────────"; \
        exit 1; \
    fi; \
    cp -a _app_src/. ./; \
    cp -a _shared_src/. ./; \
    rm -rf _app_src _shared_src
CMD ["python", "-u", "bot.py"]
