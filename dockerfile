# Use the ZAP Docker image (stable version) as the base image
FROM zaproxy/zap-stable:latest

# Set the working directory for your app
WORKDIR /app

# Copy your application code into the container
COPY . .

USER root

# Install Python dependencies if needed
RUN apt-get update && apt-get install -y python3-pip python3-dev build-essential supervisor
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port for ZAP API and your app
EXPOSE 5000
EXPOSE 8080 

# Create a supervisor configuration file
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Start supervisord, which will manage both ZAP and Flask app
CMD ["/usr/bin/supervisord"]
