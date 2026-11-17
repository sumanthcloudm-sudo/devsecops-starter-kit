FROM python:3.13-alpine

# Apply available Alpine security updates to packages in the base image.
RUN apk upgrade --no-cache

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# This sample only uses requests, not sqlite3. Remove SQLite only if the
# package manager can do so without breaking other declared dependencies.
# Verify Python, TLS and requests work before accepting the resulting image.
RUN apk del sqlite-libs \
    && python -c "import ssl, requests; print('Python/TLS/requests smoke test passed')"

COPY . .

CMD ["python", "--version"]
