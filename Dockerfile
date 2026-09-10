FROM python:3.11-slim
WORKDIR /lab
COPY vulnerable-app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "vulnerable-app/app.py"]
