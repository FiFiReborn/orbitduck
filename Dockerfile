# syntax=docker/dockerfile:1.7


ARG PYTHON_VERSION=3.12
ARG DEBIAN_FRONTEND=noninteractive


############################
# Builder (installs wheels)
############################
FROM python:${PYTHON_VERSION}-slim AS builder


WORKDIR /wheels
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*


COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


############################
# Runtime
############################
FROM python:${PYTHON_VERSION}-slim AS runtime


# Install system deps & nmap toolkit
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        ncat \
        iputils-ping \
        netcat-traditional \
        traceroute \
    && rm -rf /var/lib/apt/lists/*


# Non-root user for safety
ARG APP_USER=app
RUN useradd -m -u 1000 ${APP_USER}
USER ${APP_USER}


WORKDIR /app


# Copy wheels and install
COPY --chown=${APP_USER}:${APP_USER} --from=builder /wheels /wheels
COPY --chown=${APP_USER}:${APP_USER} requirements.txt ./
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt


# Copy source
COPY --chown=${APP_USER}:${APP_USER} src ./src
COPY --chown=${APP_USER}:${APP_USER} pyproject.toml ./
COPY --chown=${APP_USER}:${APP_USER} tests ./tests



ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1


# Default command runs the CLI
ENTRYPOINT ["python", "-m", "orbitduck.cli"]
CMD ["--help"]