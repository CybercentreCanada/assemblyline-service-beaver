FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH beaver.beaver.Beaver

RUN pip install mysql-connector-python && rm -rf ~/.cache/pip

# Switch to assemblyline user
USER assemblyline

# Copy APKaye service code
WORKDIR /opt/al_service
COPY . .