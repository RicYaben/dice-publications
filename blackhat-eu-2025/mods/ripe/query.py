from dice.repo import Repository
import duckdb

def query_prefixes(repo: Repository) -> list[str]:
    q = """
    SELECT DISTINCT prefix
    FROM (
        SELECT resource AS prefix FROM records_resources
        UNION ALL
        SELECT prefix FROM unnest(prefixes) AS t(prefix)
    ) AS all_prefixes
    """
    try:
        res = repo.get_connection().execute(q).fetchall()
        return [row[0] for row in res]
    # The table may not exist yet
    except duckdb.CatalogException:
        print("table records_resources not loaded yet")
        return []