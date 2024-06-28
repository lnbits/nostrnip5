async def m001_initial_invoices(db):

    await db.execute(
        f"""
       CREATE TABLE nostrnip5.domains (
           id TEXT PRIMARY KEY,
           wallet TEXT NOT NULL,

           currency TEXT NOT NULL,
           amount INTEGER NOT NULL,

           domain TEXT NOT NULL,

           time TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
       );
   """
    )

    await db.execute(
        f"""
       CREATE TABLE nostrnip5.addresses (
           id TEXT PRIMARY KEY,
           domain_id TEXT NOT NULL,

           local_part TEXT NOT NULL,
           pubkey TEXT NOT NULL,

           active BOOLEAN NOT NULL DEFAULT false,

           time TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},

           FOREIGN KEY(domain_id) REFERENCES {db.references_schema}domains(id)
        );
   """
    )


async def m002_add_owner_id_to_addresess(db):
    """
    Adds owner_id column to  addresses.
    """
    await db.execute("ALTER TABLE nostrnip5.addresses ADD COLUMN owner_id TEXT")


async def m003_add_cost_extra_column_to_domains(db):
    """
    Adds cost_extra column to  addresses.
    """
    await db.execute("ALTER TABLE nostrnip5.domains ADD COLUMN cost_extra TEXT")


async def m004_add_domain_rankings_table(db):

    await db.execute(
        """
       CREATE TABLE nostrnip5.domain_rankings (
           name TEXT PRIMARY KEY,
           rank INTEGER NOT NULL

       );
   """
    )


async def m005_add_domain_rankings_table(db):

    await db.execute(
        """
       CREATE TABLE nostrnip5.settings (
           owner_id TEXT PRIMARY KEY,
           settings text

       );
   """
    )
