use rusqlite::{Connection, OptionalExtension, Params, Row};

use crate::StoreResult;

pub(crate) fn query_opt<T>(
    conn: &Connection,
    sql: &str,
    params: impl Params,
    decode: impl FnOnce(&Row<'_>) -> rusqlite::Result<StoreResult<T>>,
) -> StoreResult<Option<T>> {
    conn.query_row(sql, params, decode).optional()?.transpose()
}

pub(crate) fn query_vec<T>(
    conn: &Connection,
    sql: &str,
    params: impl Params,
    decode: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
) -> StoreResult<Vec<T>> {
    let mut stmt = conn.prepare(sql)?;
    Ok(stmt.query_map(params, decode)?.collect::<Result<_, _>>()?)
}
