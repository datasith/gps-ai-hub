#!/usr/bin/env python3
"""
deploy_portal.py — Deploys the Self-Contained Compliance & eDiscovery Review Portal
(`ge-ediscovery-portal`) to Google Cloud Run.

Builds the multi-stage container image (`portal/Dockerfile` -> React 18 SPA + Python
BigQuery/GCS API server) and deploys it to Cloud Run using the least-privilege
harvester/portal service account.
"""

import argparse
import os
import subprocess
import sys

DEFAULT_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")
DEFAULT_REGION = os.environ.get("CLOUD_RUN_REGION", "us-central1")
SERVICE_NAME = os.environ.get("PORTAL_SERVICE_NAME", "ge-ediscovery-portal")


def run_cmd(cmd: list[str]) -> str:
    print(f"  $ {' '.join(cmd)}")
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return out.decode("utf-8").strip()
    except subprocess.CalledProcessError as e:
        print(e.output.decode("utf-8", errors="replace"))
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy the Gemini Enterprise eDiscovery Review Portal to Cloud Run.")
    parser.add_argument("--project-id", default=DEFAULT_PROJECT_ID, help="Google Cloud Project ID")
    parser.add_argument("--region", default=DEFAULT_REGION, help="Cloud Run region (default: us-central1)")
    parser.add_argument("--service-name", default=SERVICE_NAME, help="Cloud Run service name (default: ge-ediscovery-portal)")
    parser.add_argument("--bucket-name", default="", help="GCS compliance archive bucket (default: <project_id>-ge-ediscovery)")
    parser.add_argument("--bq-dataset", default="ge_ediscovery", help="BigQuery dataset name (default: ge_ediscovery)")
    parser.add_argument("--reviewer-email", default="", help="Optional default reviewer email shown in portal header")
    parser.add_argument("--iap", action="store_true", help="Enable native Cloud Run Identity-Aware Proxy (IAP) for direct browser Google Sign-In")
    parser.add_argument("--iap-accessor", default="", help="Optional IAM principal to grant roles/iap.httpsResourceAccessor (e.g. domain:example.com or user:reviewer@example.com)")
    args = parser.parse_args()

    if not args.project_id:
        print("Error: --project-id (or GCP_PROJECT_ID) is required.")
        sys.exit(1)

    bucket_name = args.bucket_name or f"{args.project_id}-ge-ediscovery"
    sa_email = f"ge-ediscovery-harvester-sa@{args.project_id}.iam.gserviceaccount.com"
    portal_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "portal")

    # Ensure all file timestamps in portal/ are >= 1980 for Cloud Build ZIP packaging
    import time
    now = time.time()
    for root, _dirs, files in os.walk(portal_dir):
        if "node_modules" in root:
            continue
        try:
            os.utime(root, (now, now))
        except OSError:
            pass
        for fname in files:
            try:
                os.utime(os.path.join(root, fname), (now, now))
            except OSError:
                pass

    env_vars = [
        f"GCP_PROJECT_ID={args.project_id}",
        f"GCS_BUCKET_NAME={bucket_name}",
        f"BQ_DATASET={args.bq_dataset}",
    ]
    if args.reviewer_email:
        env_vars.append(f"PORTAL_REVIEWER_EMAIL={args.reviewer_email}")

    print("======================================================================")
    print(f"Deploying Compliance Review Portal ({args.service_name}) to Cloud Run")
    print("======================================================================")
    deploy_cmd = [
        "gcloud", "run", "deploy", args.service_name,
        f"--project={args.project_id}",
        f"--region={args.region}",
        f"--source={portal_dir}",
        f"--service-account={sa_email}",
        "--no-allow-unauthenticated",
        f"--set-env-vars={','.join(env_vars)}",
        "--memory=512Mi",
        "--cpu=1",
        "--quiet",
    ]
    if args.iap:
        run_cmd(["gcloud", "services", "enable", "iap.googleapis.com", f"--project={args.project_id}"])
        deploy_cmd.append("--iap")
    run_cmd(deploy_cmd)

    if args.iap and args.iap_accessor:
        run_cmd([
            "gcloud", "iap", "web", "add-iam-policy-binding",
            f"--project={args.project_id}",
            "--resource-type=cloud-run",
            f"--service={args.service_name}",
            f"--region={args.region}",
            f"--member={args.iap_accessor}",
            "--role=roles/iap.httpsResourceAccessor",
        ])

    service_url = run_cmd([
        "gcloud", "run", "services", "describe", args.service_name,
        f"--project={args.project_id}",
        f"--region={args.region}",
        "--format=value(status.url)",
    ])
    print("\n======================================================================")
    print("PORTAL DEPLOYMENT COMPLETE")
    print("======================================================================")
    print(f"  Cloud Run Service URL: {service_url}")
    print(f"  Local Authenticated Proxy: gcloud run services proxy {args.service_name} --project={args.project_id} --region={args.region} --port=8085")


if __name__ == "__main__":
    main()
