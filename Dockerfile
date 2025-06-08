FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tshark \
    libpcap-dev \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create necessary directories
RUN mkdir -p data/output data/models

# Expose port for Flask web interface
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"] 