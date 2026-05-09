# EC2 Deployment

This guide deploys PayloadWeaver on a single Amazon EC2 instance using Docker. The container runs both the Flask app and OWASP ZAP through Supervisor.

## 1. Launch EC2

Recommended starting point:

- AMI: Amazon Linux 2023
- Instance type: `t3.medium` or larger, because OWASP ZAP needs memory during scans
- Storage: 20 GB or more
- Security group inbound rules:
  - SSH `22` from your IP only
  - App port `5000` from your IP for testing, or from the internet only if you intentionally want it public
  - Do not expose ZAP port `8080`

For a stable URL, allocate and associate an Elastic IP with the instance.

## 2. SSH Into The Instance

```bash
ssh -i your-key.pem ec2-user@YOUR_EC2_PUBLIC_IP
```

## 3. Install Docker

```bash
sudo yum update -y
sudo yum install -y docker git
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker ec2-user
exit
```

SSH back in after `exit` so the Docker group permission applies.

Install the Docker Compose plugin if it is not already available:

```bash
docker compose version
```

If that command fails:

```bash
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -SL https://github.com/docker/compose/releases/download/v2.27.0/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
docker compose version
```

## 4. Upload Or Clone The Project

Option A, clone from Git:

```bash
git clone YOUR_REPOSITORY_URL Web-fuzzer
cd Web-fuzzer
```

Option B, copy from your computer:

```bash
scp -i your-key.pem -r Web-fuzzer ec2-user@YOUR_EC2_PUBLIC_IP:/home/ec2-user/
ssh -i your-key.pem ec2-user@YOUR_EC2_PUBLIC_IP
cd Web-fuzzer
```

## 5. Create Production Environment File

```bash
cp .env.example .env
nano .env
```

The `.env` file must contain only `KEY=value` lines. Do not put commands such as `cd ...`, quotes around variable names, or PowerShell syntax in this file.

Set at least:

```env
SECRET_KEY=use-a-long-random-value
OPENAI_API_KEY=your-openai-key-if-you-use-ai-mode
ZAP_API_KEY=use-a-long-random-value
ZAP_DISABLE_KEY=false
PORT=5000
ZAP_PORT=8080
```

Generate secret values on the instance:

```bash
openssl rand -hex 32
```

## 6. Build And Run

```bash
docker compose -f docker-compose.ec2.yml up -d --build
```

Check status and logs:

```bash
docker ps
docker logs -f payloadweaver
```

Health check:

```bash
curl http://127.0.0.1:5000/health
```

Open the app in your browser:

```text
http://YOUR_EC2_PUBLIC_IP:5000
```

## 7. Update A Running Deployment

If you cloned from Git:

```bash
cd ~/Web-fuzzer
git pull
docker compose -f docker-compose.ec2.yml up -d --build
```

If you copied files manually, upload the new files, then run:

```bash
docker compose -f docker-compose.ec2.yml up -d --build
```

## 8. Stop Or Restart

```bash
docker compose -f docker-compose.ec2.yml restart
docker compose -f docker-compose.ec2.yml down
```

The Compose file stores SQLite data and generated reports in Docker volumes:

- `payloadweaver-instance`
- `payloadweaver-reports`

## 9. Optional: Put Nginx In Front

For production, use Nginx with HTTPS and keep the app container bound to `5000`. Open ports `80` and `443` in the EC2 security group, then proxy traffic to `http://127.0.0.1:5000`.

Do not expose OWASP ZAP port `8080` publicly.

## Troubleshooting

If the app opens but scans fail:

```bash
docker exec -it payloadweaver bash
curl http://127.0.0.1:8080/JSON/core/view/version/
```

If the Docker build fails during `pip install`, verify `requirements.txt` is present and rebuild:

```bash
docker compose -f docker-compose.ec2.yml build --no-cache
```

If the browser cannot connect:

- Check `docker ps` shows port `5000`
- Check the EC2 security group allows inbound `5000`
- Check the instance public IP or Elastic IP
- Check logs with `docker logs payloadweaver`
