# Use a slim Python image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Copy dependency list first (helps with Docker caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your project code into the container
COPY . .

# Set the entrypoint so running the container runs your scanner
ENTRYPOINT ["python", "src/scanner.py"]