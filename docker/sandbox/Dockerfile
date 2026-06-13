FROM node:20-slim
RUN apt-get update && apt-get install -y \
    chromium tesseract-ocr libnss3 \
    libatk1.0-0 libcups2 libdrm2 \
    libxkbcommon0 libgbm1 libasound2 \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY crawler.js ./
ENTRYPOINT ["node", "crawler.js"]
