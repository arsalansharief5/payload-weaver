# PayloadWeaver

PayloadWeaver is a Flask-based web security scanning platform that combines an authenticated web UI, OWASP ZAP-powered crawling and scanning, PDF report generation, and optional AI-assisted analysis for category classification and mitigation guidance.

It is designed for teams that want a lightweight security review workflow they can run locally or deploy to AWS using Docker and Amazon ECS.

## Table of Contents
- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Environment Variables](#environment-variables)
- [Local Development Setup](#local-development-setup)
- [Docker Setup](#docker-setup)
- [Deployment AWS ECS / Production](#deployment-aws-ecs--production)
- [CI/CD Pipeline](#cicd-pipeline)
- [Troubleshooting](#troubleshooting)
- [Additional Notes](#additional-notes)

## Project Overview
### What the application does
PayloadWeaver lets a user submit one or more target URLs through a web interface. The application then:

1. Connects to OWASP ZAP.
2. Crawls the target site to discover reachable URLs.
3. Runs a scan profile such as `quick`, `regular`, `deep`, or `ai_assisted`.
4. Collects ZAP alerts and normalizes them into a structured result set.
5. Optionally uses OpenAI to classify the website into one of eight categories and generate smart mitigation notes.
6. Stores scan metadata in a SQLite database by default.
7. Generates a downloadable PDF report.

### Key features and purpose
- Role-based access for users, testers, and admins
- Website crawling through OWASP ZAP spider
- Passive and active scan profiles
- AI-assisted site classification and mitigation summaries
- PDF report generation
- Assignment workflow for testers
- ECS-ready containerization with Gunicorn and Supervisor
- Health check endpoint for load balancers and container orchestration

### Target users and use cases
- Students building a web security review project
- Internal app security teams who want a lightweight review portal
- Developers who want a dashboard around OWASP ZAP scans
- Teams experimenting with AI-assisted remediation reporting

## Architecture
### High-level system design
PayloadWeaver is a monolithic web application with a few clear responsibilities:

| Layer | Responsibility |
|---|---|
| Frontend | Server-rendered Jinja templates for login, scanner, dashboard, results, and assignment flows |
| Backend | Flask application for routing, auth, scan orchestration, database access, and report generation |
| Scanning Engine | OWASP ZAP daemon used for crawling, passive scanning, and active scanning |
| AI Layer | OpenAI API used for website category classification and mitigation summaries |
| Persistence | SQLite by default for user and scan metadata |
| Reporting | ReportLab-based PDF generation |

### Runtime flow
1. A user authenticates in the Flask web app.
2. The `/start_scan` route receives a target URL and scan mode.
3. The backend connects to ZAP through the Python ZAP client.
4. `crawler.py` runs the ZAP spider.
5. `attack.py` runs passive and optional active scanning, then collects ZAP alerts.
6. `utils.py` optionally calls OpenAI to classify the site and summarize findings.
7. `report_generator.py` creates a PDF report.
8. The result is rendered in the UI and stored for later review.

### Deployment architecture
The current container model runs the Flask app and ZAP in the same container using Supervisor. For AWS, the recommended production architecture is:

- Amazon ECS Fargate service
- Application Load Balancer in front of the service
- Amazon ECR for container image storage
- AWS CodeBuild and optionally CodePipeline for build and deploy automation
- CloudWatch Logs for application and container logs
- AWS Secrets Manager for API keys and secret values
- Optional Amazon RDS and Amazon S3 or EFS for persistent storage

Recommended production topology:

```text
User Browser
    |
    v
Application Load Balancer
    |
    v
ECS Service (Fargate)
    |
    +-- Flask app (Gunicorn)
    +-- OWASP ZAP daemon
    |
    +-- Secrets Manager for secrets
    +-- CloudWatch Logs for logging
    +-- Optional RDS for database
    +-- Optional S3 or EFS for report storage
```

### External dependencies
- OWASP ZAP
- OpenAI API
- Flask
- Flask-Login
- Flask-SQLAlchemy
- Flask-Migrate
- ReportLab
- Gunicorn
- Supervisor
- Docker
- AWS ECS, ECR, ALB, CloudWatch, and Secrets Manager for production deployment

## Project Structure
```text
.
├── .github/
│   └── workflows/
│       └── deploy.yml
├── custompayloads/
│   └── custompayloads/
├── instance/
│   └── site.db
├── migrations/
├── static/
│   ├── reports/
│   └── ...
├── templates/
│   ├── base_modern.html
│   ├── index_modern.html
│   ├── results_modern.html
│   ├── dashboard_modern.html
│   └── ...
├── app.py
├── attack.py
├── buildspec.yml
├── connection.py
├── crawler.py
├── Dockerfile
├── dockerfile
├── main.py
├── report_generator.py
├── requirements.txt
├── supervisord.conf
├── utils.py
└── README.md
```

### Important files and directories
| Path | Purpose |
|---|---|
| `app.py` | Main Flask application, routes, models, auth, scan orchestration, health endpoint |
| `connection.py` | ZAP client connection logic and proxy endpoint discovery |
| `crawler.py` | ZAP spider wrapper for crawling target URLs |
| `attack.py` | ZAP passive and active scan orchestration and alert normalization |
| `utils.py` | Website text extraction, OpenAI-based category classification, AI mitigation summary generation |
| `report_generator.py` | PDF generation for scan reports |
| `templates/` | Jinja templates for frontend pages |
| `static/` | Static assets and generated PDF reports |
| `instance/site.db` | Default SQLite database used locally |
| `migrations/` | Database migration scaffolding via Flask-Migrate/Alembic |
| `Dockerfile` | Production-oriented container build |
| `supervisord.conf` | Starts ZAP and Gunicorn in the same container |
| `buildspec.yml` | AWS CodeBuild instructions for building and pushing to ECR |
| `.github/workflows/deploy.yml` | GitHub Actions workflow that builds and pushes to Docker Hub |
| `main.py` | Older terminal-based entry point, not the primary web runtime |
| `custompayloads/` | Legacy category payload files retained from older scan flow experiments |

## Prerequisites
### Required tools
- Python 3.11 or newer recommended
- `pip`
- Virtual environment support
- Docker
- AWS CLI for AWS deployment workflows
- An OWASP ZAP-capable container runtime if testing in Docker

### Required accounts or services
- OpenAI account and API key for AI-assisted mode
- AWS account for ECS deployment
- Amazon ECR repository for image storage

## Environment Variables
PayloadWeaver uses environment variables for runtime configuration. In local development you can set them in PowerShell or place them in a `.env` file. In production on ECS, use environment variables and Secrets Manager.

### Required variables
| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | Flask session secret key |
| `OPENAI_API_KEY` | Required for AI mode | API key used for website classification and mitigation summaries |

### Scan and AI settings
| Variable | Required | Description | Default |
|---|---|---|---|
| `OPENAI_MODEL` | No | OpenAI model name for AI features | `gpt-4.1-mini` |
| `ZAP_API_KEY` | Recommended | API key for OWASP ZAP if API key auth is enabled | none |
| `ZAP_PROXY_URL` | No | Explicit ZAP base URL such as `http://127.0.0.1:8080` | auto-discovery list |
| `ZAP_PORT` | No | ZAP daemon port inside container | `8080` |
| `ZAP_DISABLE_KEY` | No | Whether to disable ZAP API key checks in the container | `false` |

### Flask and container runtime
| Variable | Required | Description | Default |
|---|---|---|---|
| `PORT` | No | Port exposed by Gunicorn/Flask | `5000` |
| `FLASK_HOST` | No | Flask host when running `python app.py` | `0.0.0.0` |
| `FLASK_DEBUG` | No | Enable Flask debug mode for local development only | `false` |
| `GUNICORN_WORKERS` | No | Number of Gunicorn workers | `2` |
| `GUNICORN_TIMEOUT` | No | Gunicorn worker timeout in seconds | `180` |

### Database
| Variable | Required | Description | Default |
|---|---|---|---|
| `DATABASE_URL` | No | Database connection string | `sqlite:///site.db` |

### Example `.env` file
```env
SECRET_KEY=change-this-for-local-dev
OPENAI_API_KEY=your-openai-api-key
OPENAI_MODEL=gpt-4.1-mini
ZAP_API_KEY=change-this-if-zap-key-auth-is-enabled
ZAP_PROXY_URL=http://127.0.0.1:8080
PORT=5000
FLASK_HOST=0.0.0.0
FLASK_DEBUG=false
GUNICORN_WORKERS=2
GUNICORN_TIMEOUT=180
DATABASE_URL=sqlite:///site.db
ZAP_PORT=8080
ZAP_DISABLE_KEY=false
```

### Managing environment variables
#### Local
Use PowerShell:

```powershell
$env:SECRET_KEY = "dev-secret"
$env:OPENAI_API_KEY = "your-key"
$env:ZAP_PROXY_URL = "http://127.0.0.1:8080"
```

Or place values in `.env` and use the included `python-dotenv` support.

#### Production
- Put non-secret values in ECS task definition environment variables
- Put secrets in AWS Secrets Manager and reference them in ECS task definition `secrets`
- Never commit real credentials into the repository

## Local Development Setup
### 1. Clone the repository
```powershell
git clone <your-repository-url>
cd Web-fuzzer
```

### 2. Create and activate a virtual environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies
```powershell
pip install -r requirements.txt
```

### 4. Configure environment variables
Either create a `.env` file or export environment variables manually.

Example PowerShell session:
```powershell
$env:SECRET_KEY = "dev-secret"
$env:OPENAI_API_KEY = "your-openai-key"
$env:ZAP_PROXY_URL = "http://127.0.0.1:8080"
```

### 5. Start OWASP ZAP
You need ZAP running locally if you are not using the bundled Docker container.

Example:
- Start OWASP ZAP Desktop and enable API access
- Or run ZAP daemon mode manually

### 6. Run the application
```powershell
.\venv\Scripts\python.exe app.py
```

Open:
```text
http://127.0.0.1:5000
```

### 7. Health check
```text
http://127.0.0.1:5000/health
```

Expected response:
```json
{"status":"ok"}
```

## Docker Setup
The Docker image packages both OWASP ZAP and the Flask app in one container. Supervisor manages both processes and Gunicorn serves the Flask application.

### Build the image
```powershell
docker build -f Dockerfile -t payloadweaver:local .
```

### Run the container locally
```powershell
docker run --rm -p 5000:5000 -p 8080:8080 `
  -e SECRET_KEY="dev-secret" `
  -e OPENAI_API_KEY="your-openai-key" `
  -e ZAP_API_KEY="your-zap-key" `
  -e ZAP_DISABLE_KEY=false `
  -e PORT=5000 `
  payloadweaver:local
```

### What the Dockerfile does
- Uses the official OWASP ZAP stable image as the base
- Installs Python, Supervisor, and required build packages
- Installs Python dependencies
- Copies the application code
- Creates directories for local database and report output
- Exposes ports `5000` and `8080`
- Starts Supervisor, which launches:
  - OWASP ZAP daemon
  - Gunicorn serving the Flask app

## Deployment AWS ECS / Production
### Recommended production approach
Deploy the container to Amazon ECS Fargate behind an Application Load Balancer. Use:
- ECR for image storage
- CloudWatch Logs for logs
- Secrets Manager for secrets
- Optional RDS and S3 or EFS for persistence

### Important production note
The default local setup uses SQLite and writes reports to local disk. In ECS/Fargate, container storage is ephemeral. For production:
- Prefer RDS instead of SQLite
- Prefer S3 or EFS for report files

### Step 1. Create an ECR repository
```bash
aws ecr create-repository --repository-name payload-weaver --region ap-south-1
```

### Step 2. Build and push the image to ECR
```bash
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_DEFAULT_REGION=ap-south-1
REPOSITORY_URI=$AWS_ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com/payload-weaver

aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $REPOSITORY_URI

docker build -f Dockerfile -t payload-weaver:latest .
docker tag payload-weaver:latest $REPOSITORY_URI:latest
docker push $REPOSITORY_URI:latest
```

### Step 3. Create an ECS task definition
Configure:
- Launch type: Fargate
- Network mode: `awsvpc`
- CPU and memory appropriate for ZAP plus Flask
- Container port: `5000`
- Health check endpoint: `/health`
- CloudWatch log driver
- Environment variables and secrets

Suggested environment variables:
- `PORT=5000`
- `FLASK_DEBUG=false`
- `ZAP_PORT=8080`
- `ZAP_DISABLE_KEY=false`
- `ZAP_PROXY_URL=http://127.0.0.1:8080`

Suggested ECS secrets:
- `SECRET_KEY`
- `OPENAI_API_KEY`
- `ZAP_API_KEY`

### Step 4. Create an ECS service
- Create or select an ECS cluster
- Create a Fargate service
- Attach the task definition
- Set desired count
- Attach it to an ALB target group

### Step 5. Configure the Application Load Balancer
- Listener: `80` or `443`
- Target group target type: `ip`
- Target port: `5000`
- Health check path: `/health`

### Step 6. Configure networking
- Public subnets for ALB
- Private or public subnets for ECS tasks depending on design
- Security group for ALB allowing inbound `80` and optionally `443`
- Security group for ECS tasks allowing inbound `5000` from the ALB security group
- Outbound internet access for ECS tasks if calling OpenAI

### Step 7. Configure IAM roles and permissions
#### Task execution role
Needs permissions for:
- pulling images from ECR
- writing logs to CloudWatch
- reading secrets from Secrets Manager if used

#### Task role
Needs permissions only if the app itself must call AWS services directly, such as:
- S3 for report storage
- Secrets Manager direct API access

### Step 8. Production data handling
#### Database
Recommended:
- move to Amazon RDS

If you stay with SQLite:
- mount EFS
- understand this is not ideal for scaling

#### Reports
Recommended:
- store generated reports in S3

Alternative:
- use EFS if keeping the current filesystem-based report approach

## CI/CD Pipeline
### AWS build pipeline
The repository includes [buildspec.yml](buildspec.yml), which is designed for AWS CodeBuild and can be plugged into CodePipeline.

Pipeline flow:
1. Source stage from your repository
2. CodeBuild stage
   - logs in to ECR
   - builds the Docker image
   - tags image with commit hash and `latest`
   - pushes both tags to ECR
   - generates `imagedefinitions.json`
3. Deployment stage
   - ECS uses `imagedefinitions.json` to update the service

### GitHub Actions workflow
The repository also includes [.github/workflows/deploy.yml](.github/workflows/deploy.yml), which currently:
- builds the Docker image
- pushes it to Docker Hub

This is useful if:
- you want a simple external registry workflow
- or you want to test image publishing outside AWS

### Important configuration details
- Ensure CodeBuild has permission to:
  - access ECR
  - get AWS account identity
  - push images
- Ensure the ECS deployment stage references the correct container name from `imagedefinitions.json`
- Ensure your task definition container name matches `CONTAINER_NAME` in `buildspec.yml`

## Troubleshooting
### Common issues and fixes
| Issue | Likely cause | Fix |
|---|---|---|
| `Could not connect to OWASP ZAP` | ZAP not running or wrong proxy URL | Set `ZAP_PROXY_URL` correctly and verify ZAP is running |
| `/home` loads but scans fail | ZAP unavailable inside local or container runtime | Start ZAP or verify Supervisor started the daemon |
| AI classification unavailable | Missing or invalid `OPENAI_API_KEY`, or API quota issue | Verify API key, billing, quota, and outbound network access |
| PDF downloads fail after restart | Local files stored in ephemeral container filesystem | Use S3 or EFS in production |
| Session/auth problems | Weak or missing `SECRET_KEY` | Set a strong `SECRET_KEY` in env or Secrets Manager |
| ECS tasks restart repeatedly | Health check failing or app process crashing | Check `/health`, CloudWatch logs, ECS events, and container startup commands |
| Build fails in CodeBuild | Wrong Dockerfile path or missing permissions | Use `Dockerfile`, verify IAM, and inspect build logs |

### Logs and debugging tips
#### Local
- Check terminal output from `python app.py`
- Check `flask_run.log` if you are redirecting output
- Use the `/logs` SSE endpoint in the UI for scan progress

#### Docker
- `docker logs <container-id>`

#### ECS
- CloudWatch Logs for container stdout and stderr
- ECS service events for deployment and health failures
- ALB target group health status

### Useful checks
```bash
curl http://127.0.0.1:5000/health
```

```bash
aws ecs describe-services --cluster <cluster-name> --services <service-name>
```

```bash
aws logs tail /aws/ecs/<your-log-group> --follow
```

## Additional Notes
### Best practices
- Use Secrets Manager for secrets in production
- Use a managed database instead of SQLite for real deployments
- Store reports in S3 or EFS rather than container-local storage
- Run with `FLASK_DEBUG=false` in all non-local environments
- Keep OWASP ZAP API protected in production

### Security considerations
- Do not commit `.env` with real secrets
- Rotate any API keys that were ever exposed in logs or chat
- Limit ALB and ECS security groups to required ports only
- Restrict IAM policies to the minimum permissions required
- Be careful about scanning only targets you are authorized to test

### Future improvements
- Replace SQLite with PostgreSQL or MySQL via RDS
- Move report storage to S3
- Split Flask and ZAP into separate ECS containers within one task or separate services
- Add structured application logging
- Add automated database migrations in deployment workflows
- Add Terraform or CloudFormation for infrastructure-as-code

---

If you are using this project for production or assessment work, start by validating the local flow first, then containerize, then move to ECS with proper secrets and persistent storage. This project is easiest to operate when ZAP connectivity, environment variables, and report persistence are addressed early in the deployment process.
