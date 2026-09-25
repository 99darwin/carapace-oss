"""The single Alembic migration matches the ORM models and round-trips."""

from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from carapace_server.models import Base

SERVER_DIR = Path(__file__).resolve().parents[1]


def _config(db_path: Path) -> Config:
    config = Config(str(SERVER_DIR / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    config.attributes["configure_logger"] = False
    return config


def test_upgrade_matches_models_and_downgrades(tmp_path: Path) -> None:
    db_path = tmp_path / "migrate.db"
    config = _config(db_path)
    command.upgrade(config, "head")

    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(connection)
            diff = compare_metadata(context, Base.metadata)
        assert diff == []

        command.downgrade(config, "base")
        with engine.connect() as connection:
            assert inspect(connection).get_table_names() == ["alembic_version"]
    finally:
        engine.dispose()
