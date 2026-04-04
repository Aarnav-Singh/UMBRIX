# Deploying UMBRIX Command Center

UMBRIX is a full-stack cybersecurity posture visualization platform. It supports a **Hybrid Distribution Architecture**, allowing you to run it completely air-gapped on-premise, or deploy it into modern cloud environments via IaC (Infrastructure as Code).

---

## 1. On-Premise Installation (Self-Hosted for Enterprises)

Use our CLI installer scripts to rapidly deploy the entire UMBRIX stack (Frontend, FastAPI, Postgres, Redis, Clickhouse) using Docker. This ensures data completely remains inside your own firewalls.

### Prerequisites

- Docker and Docker Compose installed.
- Minimum 4GB RAM allocated to Docker.

### Linux & macOS

1. Open your terminal in the UMBRIX root directory.
2. Make the installer script executable and run it:

   ```bash
   chmod +x scripts/install/install.sh
   ./scripts/install/install.sh
   ```


### Windows (PowerShell)

1. Open PowerShell as Administrator in the UMBRIX root directory.
2. Execute the setup script:

   ```powershell
   .\scripts\install\install.ps1
   ```


**What the installer does:**

- Verifies system dependencies.
- Generates a highly secure `.env.prod` file with 64-character JWT secrets and random database passwords.
- Compiles the Production variants of the Next.js and Python API containers.
- Orchestrates them up silently using `docker-compose.prod.yml`.

Accessing your platform:

- Dashboard: `http://localhost:3000`
- API Swagger: `http://localhost:8000/docs`
- Grafana Metrics: `http://localhost:3001`

---

## 2. Cloud Native Deployment (SaaS)

If you do not have on-prem servers or wish to expose the platform securely to remote workers, use our direct Cloud Integrations.

### Backend (Render / Railway / AWS)

We have included a `render.yaml` blueprint. This utilizes "Infrastructure as Code" to set up your entire backend ecosystem on [Render.com](https://render.com).

1. Create an account on Render.
2. Connect your GitHub repository containing UMBRIX.
3. Render will automatically detect the `render.yaml` script at the root.
4. Click **Deploy**. Render will automatically provision:
   - A Managed PostgreSQL instance.
   - A Managed Redis Cache.
   - The Python FastAPI Web Service (`umbrix-api`).
   - The Kafka Event Consumer background worker (`umbrix-worker`).

*Alternative for Heavy Enterprise:* See `infra/helm/umbrix/` for deploying cleanly onto AWS EKS or Google GKE using Kubernetes Helm Charts.

### Frontend (Vercel)

The Dashboard is built using Next.js 14 and is fully optimized for **Vercel** Edge deployments.

1. Create a project on [Vercel](https://vercel.com).
2. Connect this repository and set the Root Directory to `frontend`.
3. In Environment Variables, add your backend's external Render URL:
   - `NEXT_PUBLIC_API_URL=https://umbrix-api-xxxx.onrender.com/api/v1`
4. Click **Deploy**.

**Important CORS configuration:**
Once your Vercel site is live (e.g. `umbrix.vercel.app`), go to your Render Dashboard for `umbrix-api` and update the `CORS_ORIGINS` environment variable to `["https://umbrix.vercel.app"]` to securely allow your frontend to speak to your backend.
