# Docker Deployment Guide

## StubForge Mobile Docker Usage

This guide explains how to run StubForge Mobile in Docker with custom stubs and keys.

## Quick Start (Built-in Samples)

Run with built-in samples - perfect for getting started:

```bash
docker run -p 3000:3000 aranga/stubforge-mobile:latest
```

## Custom Stubs and Keys

### Directory Structure

Prepare your custom files in this structure:

```
my-stubforge-data/
├── stubs/
│   ├── auth/
│   │   └── login/
│   │       ├── rule.success.json
│   │       └── response.success.json
│   ├── products/
│   │   └── list/
│   │       ├── rule.products.json
│   │       └── response.products.json
│   └── custom-api/
│       └── endpoint/
│           ├── rule.json
│           └── response.json
└── keys/
    ├── private.pem
    └── public.pem
```

### Run with Custom Data

Mount your custom directories:

```bash
docker run -p 3000:3000 \
  -v ./my-stubforge-data/stubs:/app/stubs \
  -v ./my-stubforge-data/keys:/app/keys \
  aranga/stubforge-mobile:latest
```

### Persistent Data with Docker Compose

Create a `docker-compose.yml`:

```yaml
version: '3.8'
services:
  stubforge:
  image: aranga/stubforge-mobile:latest
    ports:
      - "3000:3000"
    volumes:
      - ./stubs:/app/stubs
      - ./keys:/app/keys
      - ./config:/app/config
    environment:
      - PORT=3000
```

Run with:
```bash
docker-compose up -d
```

## Volume Behavior

### Stubs Directory (`/app/stubs`)
- **Empty or missing**: Built-in sample stubs are automatically copied
- **Custom stubs present**: Your stubs are used, built-ins are ignored
- **Mixed setup**: You can mount individual subdirectories

### Keys Directory (`/app/keys`)
- **Empty or missing**: Built-in development keys are copied, or new ones generated
- **Custom keys present**: Your RSA key pair is used
- **Incomplete keys**: New key pair is automatically generated

### Configuration Directory (`/app/config`)
- Optional: Mount your `local.json` to customize endpoints and behavior
- Default: Uses built-in configuration

## Examples

### 1. Development with Built-in Samples
```bash
docker run -p 3000:3000 aranga/stubforge-mobile:latest
```

### 2. Custom Stubs, Default Keys
```bash
docker run -p 3000:3000 \
  -v ./my-stubs:/app/stubs \
  aranga/stubforge-mobile:latest
```

### 3. Production-like with Custom Everything
```bash
docker run -p 3000:3000 \
  -v ./production-stubs:/app/stubs \
  -v ./production-keys:/app/keys \
  -v ./production-config:/app/config \
  aranga/stubforge-mobile:latest
```

### 4. Individual API Endpoints
```bash
# Mount only specific stub directories
docker run -p 3000:3000 \
  -v ./my-auth-stubs:/app/stubs/auth \
  -v ./my-product-stubs:/app/stubs/products \
  aranga/stubforge-mobile:latest
```

## Building and Pushing to Docker Hub

### Build Image
```bash
docker build -t aranga/stubforge-mobile:latest .
docker build -t aranga/stubforge-mobile:1.3.0 .
```

### Push to Docker Hub
```bash
# Login to Docker Hub
docker login

# Push latest
docker push aranga/stubforge-mobile:latest

# Push versioned
docker push aranga/stubforge-mobile:1.3.0
```

### Multi-platform Build (Optional)
```bash
# Setup buildx for multi-platform
docker buildx create --use

# Build for multiple platforms
docker buildx build --platform linux/amd64,linux/arm64 \
  -t aranga/stubforge-mobile:latest \
  -t aranga/stubforge-mobile:1.3.0 \
  --push .
```

### GitHub Actions (Automated Multi-platform)

This repo includes `.github/workflows/docker-multi-platform.yml` which automatically builds and pushes `linux/amd64` and `linux/arm64` images when you push a git tag like `v1.3.3`.

1. Configure Docker Hub credentials in repository secrets:
  - `DOCKERHUB_USERNAME`
  - `DOCKERHUB_TOKEN` (Create a Docker Hub access token)
2. Create and push a tag:
```bash
git tag -a v1.3.3 -m "StubForge Mobile 1.3.3"
git push origin v1.3.3
```
3. Workflow publishes:
  - `aranga/stubforge-mobile:1.3.3`
  - `aranga/stubforge-mobile:latest`

Manual dispatch is also supported (Actions tab -> Run workflow) with a `version` input.


## Security Considerations

### Development Keys Warning
The built-in RSA keys are for **development only**. For production or sensitive testing:

1. Generate your own RSA key pair:
```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem
```

2. Mount them as volumes:
```bash
docker run -p 3000:3000 \
  -v ./secure-keys:/app/keys \
  aranga/stubforge-mobile:latest
```

### Production Deployment
- Use custom configuration with `allowDefaultClient: false`
- Implement proper network security
- Use custom RSA keys
- Consider HTTPS termination via reverse proxy

## Troubleshooting

### Container Won't Start
- Check port conflicts: `docker ps -a`
- Verify volume mounts: `docker inspect <container>`
- Check logs: `docker logs <container>`

### Custom Stubs Not Loading
- Verify volume mount path: `/app/stubs`
- Check file permissions in mounted directory
- Ensure stub files follow correct JSON format

### Key Generation Issues
- Container needs write permissions to `/app/keys`
- OpenSSL must be available (included in image)
- Check container logs for key generation messages

### Port Access Issues
- Verify port mapping: `-p 3000:3000`
- Check firewall settings
- Ensure no other services using port 3000

## Advanced Usage

### Custom Entrypoint
Override the entrypoint for debugging:
```bash
docker run -it --entrypoint /bin/sh aranga/stubforge-mobile:latest
```

### Environment Variables
```bash
docker run -p 3000:3000 \
  -e PORT=8080 \
  -e NODE_ENV=production \
  aranga/stubforge-mobile:latest
```

### Health Checks
Add health check to docker-compose.yml:
```yaml
services:
  stubforge:
  image: aranga/stubforge-mobile:latest
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:3000/.well-known/openid_configuration"]
      interval: 30s
      timeout: 10s
      retries: 3
```