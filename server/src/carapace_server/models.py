"""Import every table module so ``Base.metadata`` is complete (Alembic)."""

from carapace_server.auth import models as auth_models
from carapace_server.db import Base

__all__ = ["Base", "auth_models"]
