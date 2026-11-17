FROM python:3.13-alpine

# Apply available Alpine security updates to packages in the base image.
RUN apk upgrade --no-cache

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "--version"]
