#!/usr/bin/env python3
"""Retroactive deduplication of findings in the Mobilicustos database.

Identifies duplicate findings (same canonical_id + app_id), merges tool_sources
and metadata into the earliest survivor, updates referencing Secret and AttackPath
rows, and deletes the non-survivor duplicates.

Usage:
    python scripts/deduplicate_findings.py --dry-run   # Preview what would change
    python scripts/deduplicate_findings.py --execute    # Actually perform cleanup
"""

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Allow running from project root
sys.path.insert(0, ".")

from api.config import get_settings

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

settings = get_settings()

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def find_duplicate_groups(db: AsyncSession) -> list[dict]:
    """Find all (canonical_id, app_id) groups with more than one finding."""
    result = await db.execute(text("""
        SELECT canonical_id, app_id, COUNT(*) AS cnt
        FROM findings
        WHERE canonical_id IS NOT NULL
        GROUP BY canonical_id, app_id
        HAVING COUNT(*) > 1
        ORDER BY cnt DESC
    """))
    return [dict(row._mapping) for row in result.fetchall()]


async def get_group_findings(
    db: AsyncSession, canonical_id: str, app_id: str
) -> list[dict]:
    """Get all findings in a duplicate group, ordered by first_seen ASC."""
    result = await db.execute(
        text("""
            SELECT id, finding_id, tool_sources, severity, description,
                   poc_evidence, poc_commands, first_seen, last_seen
            FROM findings
            WHERE canonical_id = :cid AND app_id = :aid
            ORDER BY first_seen ASC
        """),
        {"cid": canonical_id, "aid": app_id},
    )
    return [dict(row._mapping) for row in result.fetchall()]


def merge_tool_sources(rows: list[dict]) -> list[str]:
    """Union all tool_sources across rows."""
    seen: set[str] = set()
    merged: list[str] = []
    for row in rows:
        sources = row.get("tool_sources") or []
        if isinstance(sources, str):
            sources = json.loads(sources)
        for t in sources:
            if t not in seen:
                seen.add(t)
                merged.append(t)
    return merged


def pick_best_severity(rows: list[dict]) -> str:
    """Return the highest severity among rows."""
    best = "info"
    for row in rows:
        sev = row.get("severity", "info")
        if SEVERITY_RANK.get(sev, 5) < SEVERITY_RANK.get(best, 5):
            best = sev
    return best


def pick_longest(rows: list[dict], field: str) -> str | None:
    """Return the longest non-None value for a field."""
    best = None
    for row in rows:
        val = row.get(field)
        if val and (best is None or len(val) > len(best)):
            best = val
    return best


def latest_timestamp(rows: list[dict], field: str) -> datetime | None:
    """Return the latest timestamp for a field."""
    best = None
    for row in rows:
        val = row.get(field)
        if val and (best is None or val > best):
            best = val
    return best


async def deduplicate(dry_run: bool) -> None:
    """Main dedup routine."""
    engine = create_async_engine(settings.database_url)
    async_session = async_sessionmaker(engine, expire_on_commit=False)

    stats = {
        "groups_processed": 0,
        "duplicates_removed": 0,
        "secrets_repointed": 0,
        "attack_paths_updated": 0,
    }

    async with async_session() as db:
        groups = await find_duplicate_groups(db)
        logger.info(f"Found {len(groups)} duplicate groups")

        for group in groups:
            cid = group["canonical_id"]
            aid = group["app_id"]
            rows = await get_group_findings(db, cid, aid)

            if len(rows) < 2:
                continue

            survivor = rows[0]  # earliest first_seen
            duplicates = rows[1:]
            dup_ids = [r["finding_id"] for r in duplicates]

            # Compute merged values
            merged_tools = merge_tool_sources(rows)
            best_severity = pick_best_severity(rows)
            best_desc = pick_longest(rows, "description")
            best_poc = pick_longest(rows, "poc_evidence")
            last_seen = latest_timestamp(rows, "last_seen")

            logger.info(
                f"  Group {cid[:40]}... : {len(rows)} findings -> "
                f"keeping {survivor['finding_id']}, removing {len(dup_ids)}"
            )

            if dry_run:
                stats["groups_processed"] += 1
                stats["duplicates_removed"] += len(dup_ids)
                continue

            # Update survivor
            await db.execute(
                text("""
                    UPDATE findings
                    SET tool_sources = :tools,
                        severity = :severity,
                        description = CASE WHEN LENGTH(:desc) > COALESCE(LENGTH(description), 0)
                                      THEN :desc ELSE description END,
                        poc_evidence = CASE WHEN LENGTH(:poc) > COALESCE(LENGTH(poc_evidence), 0)
                                       THEN :poc ELSE poc_evidence END,
                        last_seen = :last_seen
                    WHERE finding_id = :fid
                """),
                {
                    "tools": json.dumps(merged_tools),
                    "severity": best_severity,
                    "desc": best_desc or "",
                    "poc": best_poc or "",
                    "last_seen": last_seen,
                    "fid": survivor["finding_id"],
                },
            )

            # Repoint secrets referencing deleted findings
            for dup_id in dup_ids:
                result = await db.execute(
                    text("""
                        UPDATE secrets
                        SET finding_id = :survivor_id
                        WHERE finding_id = :dup_id
                    """),
                    {"survivor_id": survivor["finding_id"], "dup_id": dup_id},
                )
                stats["secrets_repointed"] += result.rowcount

            # Update attack_path finding_chain arrays
            result = await db.execute(
                text("""
                    SELECT path_id, finding_chain FROM attack_paths
                    WHERE app_id = :aid
                """),
                {"aid": aid},
            )
            for path_row in result.fetchall():
                chain = path_row.finding_chain
                if isinstance(chain, str):
                    chain = json.loads(chain)
                updated = False
                new_chain = []
                for fid in chain:
                    if fid in dup_ids:
                        if survivor["finding_id"] not in new_chain:
                            new_chain.append(survivor["finding_id"])
                        updated = True
                    else:
                        new_chain.append(fid)
                if updated:
                    await db.execute(
                        text("""
                            UPDATE attack_paths
                            SET finding_chain = :chain
                            WHERE path_id = :pid
                        """),
                        {"chain": json.dumps(new_chain), "pid": str(path_row.path_id)},
                    )
                    stats["attack_paths_updated"] += 1

            # Delete duplicate findings
            for dup_id in dup_ids:
                await db.execute(
                    text("DELETE FROM findings WHERE finding_id = :fid"),
                    {"fid": dup_id},
                )

            stats["groups_processed"] += 1
            stats["duplicates_removed"] += len(dup_ids)

        if not dry_run:
            await db.commit()
            logger.info("Changes committed.")

    # Print summary
    mode = "DRY RUN" if dry_run else "EXECUTED"
    logger.info(f"\n=== Deduplication {mode} ===")
    logger.info(f"  Groups processed:      {stats['groups_processed']}")
    logger.info(f"  Duplicates removed:    {stats['duplicates_removed']}")
    if not dry_run:
        logger.info(f"  Secrets repointed:     {stats['secrets_repointed']}")
        logger.info(f"  Attack paths updated:  {stats['attack_paths_updated']}")

    await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Deduplicate findings in DB")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="Preview changes only")
    group.add_argument("--execute", action="store_true", help="Apply changes")
    args = parser.parse_args()

    asyncio.run(deduplicate(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
