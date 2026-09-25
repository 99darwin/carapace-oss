"""Import every table module so ``Base.metadata`` is complete (Alembic)."""

from carapace_server.apikeys import models as apikey_models
from carapace_server.auth import models as auth_models
from carapace_server.db import Base
from carapace_server.store import models as store_models

__all__ = ["Base", "apikey_models", "auth_models", "store_models"]
