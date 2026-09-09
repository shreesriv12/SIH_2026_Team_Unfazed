from logging.config import fileConfig
from alembic import context
from config import settings

config = context.config
config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
if config.config_file_name: fileConfig(config.config_file_name)

def run_migrations_offline() -> None:
    context.configure(url=config.get_main_option("sqlalchemy.url"), literal_binds=True)
    with context.begin_transaction(): context.run_migrations()

def run_migrations_online() -> None:
    from sqlalchemy import create_engine
    url = settings.database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    engine = create_engine(url, pool_pre_ping=True)
    with engine.connect() as connection:
        context.configure(connection=connection)
        with context.begin_transaction(): context.run_migrations()
    engine.dispose()

run_migrations_offline() if context.is_offline_mode() else run_migrations_online()
