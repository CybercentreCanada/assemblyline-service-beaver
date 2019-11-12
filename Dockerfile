FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH beaver.beaver.Beaver

# Get required apt packages
# RUN apt-get update && apt-get install -y \
  # default-libmysqlclient-dev
  #libmysqlclient-dev

RUN pip install \
  mysql-connector-python

# Switch to assemblyline user
USER assemblyline

# Copy APKaye service code
WORKDIR /opt/al_service
COPY . .