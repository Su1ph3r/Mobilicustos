"""Seed built-in Frida scripts into the database.

Provides an upsert function that inserts new scripts or updates existing
ones based on script_name + is_builtin matching.
"""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.data.frida_scripts.seed_scripts import BUILTIN_SCRIPTS
from api.models.database import FridaScript

logger = logging.getLogger(__name__)


async def seed_builtin_scripts(db: AsyncSession) -> None:
    """Seed or update all built-in Frida scripts.

    For each script in BUILTIN_SCRIPTS:
      - If a FridaScript with the same script_name and is_builtin=True exists,
        update its mutable fields (content, description, platforms, etc.).
      - Otherwise, create a new FridaScript record.

    Args:
        db: An async SQLAlchemy session (caller is responsible for commit).
    """
    inserted = 0
    updated = 0

    for script_data in BUILTIN_SCRIPTS:
        script_name = script_data["script_name"]

        # Check for existing built-in script with this name
        stmt = select(FridaScript).where(
            FridaScript.script_name == script_name,
            FridaScript.is_builtin.is_(True),
        )
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            # Update mutable fields
            existing.script_content = script_data["script_content"]
            existing.description = script_data.get("description")
            existing.category = script_data["category"]
            existing.subcategory = script_data.get("subcategory")
            existing.platforms = script_data.get("platforms", ["android", "ios"])
            existing.target_frameworks = script_data.get("target_frameworks", [])
            existing.target_libraries = script_data.get("target_libraries", [])
            updated += 1
            logger.debug("Updated built-in script: %s", script_name)
        else:
            # Create new record
            new_script = FridaScript(
                script_name=script_data["script_name"],
                category=script_data["category"],
                subcategory=script_data.get("subcategory"),
                script_content=script_data["script_content"],
                description=script_data.get("description"),
                platforms=script_data.get("platforms", ["android", "ios"]),
                target_frameworks=script_data.get("target_frameworks", []),
                target_libraries=script_data.get("target_libraries", []),
                is_builtin=True,
                author="mobilicustos",
            )
            db.add(new_script)
            inserted += 1
            logger.debug("Inserted built-in script: %s", script_name)

    await db.commit()
    logger.info(
        "Frida script seeding complete: %d inserted, %d updated (total built-in: %d)",
        inserted,
        updated,
        len(BUILTIN_SCRIPTS),
    )
