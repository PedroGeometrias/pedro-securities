# Pedro Securities:
offers treat analysis using AlienVault OTX and VirusTotal, it can operate over IP adresses, domains, and files by hashing them, you can have a deterministic analysis over the items or by using an AI api,
you can have a non-deterministic analysis over it too. It can use those two providers by normalizing them into objects, it also stores all analysis history in a SQLite db.

## Why?
I wanted to program something that mixed Java, C and some web stuff, the reason was just to have some fun. The actual program idea came after that, because different provider send differently structured
JSON, and java offered a easy way to normalize them into an object, C was used in here mainly as a fast set of native modules, hashing, risk-score calculations and RSA-PSS signing and verification, web came as UI

## The Stack used
### Backend
- Java 17
- Spring Boot 3.5.7
- Jackson
- Maven
### Native Core
- C11 (at least, haven't tried with other)
- Make
- Bash
### Data Base
- HTML
- CSS
- Javascript

## Features
- Investigates IPv4, IPv6, domains, MD5, SHA-1, and SHA-256 indicators.
- Correlates AlienVault OTX and VirusTotal results.
- Normalizes different provider responses into `ProviderReport`.
- Calculates a deterministic and explainable risk score.
- Hashes uploaded files locally using my C SHA-256 implementation.
- Stores investigation history and compares repeated lookups.
- Maintains a SHA-256 hash chain to detect modified history records.
- Exports reports signed with RSA-PSS/SHA-256.
- Provides synthetic demo data that works without API credentials.
- Supports an optional AI-generated briefing with deterministic fallback.
  
## Quick start
This Program can run with synthetic demo data or with live data from
AlienVault OTX and VirusTotal.

Demo mode is enabled by default and does not require API keys.

### Linux with Docker

Requirements:

* Git
* Docker Engine
* Docker Compose plugin

Clone the repository and start the application:

```bash
git clone <repository-url>
cd pedro-securities
docker compose up --build
```

### Windows with Docker

Requirements:

* Git
* Docker Desktop with the WSL2 backend enabled

Open PowerShell, clone the repository, and start the application:

```powershell
git clone <repository-url>
cd pedro-securities
docker compose up --build
```

### Opening the web interface

Wait until the application finishes starting, then open:

http://localhost:8080

On Linux, you can open it from the terminal:

```bash
xdg-open http://localhost:8080
```

On Windows PowerShell:

```powershell
Start-Process http://localhost:8080
```

In demo mode, use the following synthetic indicator to test the complete
investigation flow:

```text
portal-update.example
```

Do not open `index.html` directly. The interface must be served by the Spring
Boot application because it communicates with the backend REST API.

To stop the application, press `Ctrl+C`.

To stop and remove the Docker containers:

```bash
docker compose down
```

### Linux without Docker

Requirements:

* Git
* Java 17 JDK
* Maven
* A C11-compatible compiler such as GCC or Clang
* Make
* OpenSSL development headers and libraries
* A POSIX-compatible shell

On Ubunto:

```bash
sudo apt update
sudo apt install git build-essential libssl-dev openjdk-17-jdk maven
```

Clone the repository, build the native C core, and start the application in
demo mode:

```bash
git clone <repository-url>
cd pedro-securities
make demo
```

After Spring Boot finishes starting, open:

http://localhost:8080

### Local development on Windows

The native C core uses Make and OpenSSL, so local development is not supported
directly through PowerShell.

Use either Docker Desktop or install an Ubuntu environment through WSL2 and
follow the Linux instructions inside the WSL terminal.

### Live provider mode

API keys are not included with the project. To use real AlienVault OTX and
VirusTotal data, create a local `.env` file.

On Linux:

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Edit `.env` and provide your own credentials:

```dotenv
THREATLENS_DEMO_MODE=false
OTX_API_KEY=your_otx_api_key
VT_API_KEY=your_virustotal_api_key
```

When using Docker, restart the application:

```bash
docker compose down
docker compose up --build
```

When running locally without Docker, load the environment variables and use
the live-mode target:

```bash
set -a
source .env
set +a
make run
```

### Optional AI briefing

The deterministic risk score and verdict are always available. To enable the
optional AI-generated briefing, add the following values to `.env`:

```dotenv
AI_BRIEFING_ENABLED=true
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=your_model
```

The AI integration only generates explanatory text. It does not replace or
modify the deterministic risk assessment.
