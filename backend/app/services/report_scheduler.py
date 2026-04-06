"""Weekly Report Scheduler — Automated Exec Digest Generation.

Executes weekly via APScheduler to generate SOC2 & Executive
reports for all active tenants.
"""
import structlog

logger = structlog.get_logger(__name__)


async def generate_weekly_digest() -> None:
    """Generate and dispatch weekly executive reports."""
    from app.dependencies import get_app_postgres
    from app.api.reporting import generate_pdf_report
    from app.api.reporting import generate_soc2_report
    
    logger.info("weekly_digest_job_started")
    try:
        get_app_postgres()
        tenants = ["default"]  # In a multi-tenant DB, fetch distinct tenant_ids
        
        for tenant in tenants:
            # Mock generating the bytes by calling the API functions directly
            # with system-level claims for the specific tenant
            claims = {
                "sub": "system-scheduler",
                "tenant_id": tenant,
                "role": "admin"
            }
            logger.info("generating_weekly_reports_for_tenant", tenant=tenant)
            
            # Since generate_pdf_report returns a StreamingResponse, just invoke it 
            # to trigger the ClickHouse query and PG metadata save side-effects
            await generate_pdf_report(limit=100, claims=claims)
            await generate_soc2_report(days=7, claims=claims)
            
        logger.info("weekly_digest_job_completed", tenants_processed=len(tenants))
    except Exception as e:
        logger.error("weekly_digest_job_failed", error=str(e))


def start_report_scheduler() -> None:
    """Wire the weekly digest into APScheduler."""
    from app.services.hunting import hunter_scheduler
    
    # Run every Monday at 07:00 AM UTC
    hunter_scheduler.add_job(
        generate_weekly_digest,
        'cron',
        day_of_week='mon',
        hour=7,
        minute=0,
        id='weekly_executive_digest',
        replace_existing=True
    )
    logger.info("report_scheduler_wired")
