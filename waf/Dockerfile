FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY ./waf/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./waf/ /app/waf/
COPY ./api/app/models.py /app/

RUN useradd --create-home --shell /bin/bash waf
RUN chown -R waf:waf /app
USER waf

EXPOSE 8000

CMD ["python", "-m", "waf.app.server"]
