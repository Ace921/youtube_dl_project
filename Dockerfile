# Use an official Python runtime as the base image.
FROM python:3.9-slim

# Upgrade pip to the latest version.
RUN pip install --upgrade pip

# Install dependencies required by your app.
# You can either use a requirements.txt file or install inline.
RUN pip install flask waitress yt-dlp flask-cors flask-limiter apscheduler psutil

# Create and set the working directory.
WORKDIR /app

# Copy the current directory contents into the container at /app.
COPY . /app

# Expose port 8000 so Render (or any other platform) can access your app.
EXPOSE 8000

# Define environment variables (optional).
# For example, you can set the download directory or max disk usage.
# ENV DOWNLOAD_DIR=/app/downloads
# ENV MAX_DISK_USAGE=5368709120

# Run server.py when the container launches.
CMD ["python", "server.py"]
