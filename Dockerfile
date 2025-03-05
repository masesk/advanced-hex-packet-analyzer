FROM python:3.13.2-alpine3.21
RUN apk update && apk add tshark
WORKDIR /app
COPY app . 
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Define environment variable
ENV NAME=app
# Run app.py when the container launches
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]