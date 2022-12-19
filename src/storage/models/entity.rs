use std::ops::DerefMut;
use diesel::{Expression, ExpressionMethods, Insertable, no_arg_sql_function, QueryDsl, QueryResult, RunQueryDsl, SelectableExpression, Table};
use diesel::dsl::count;
use diesel::query_dsl::methods;
use diesel::query_builder::AsChangeset;
use crate::chain::common::ChainType;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;

#[macro_use] extern crate diesel;

/// It's interesting to know which SQLite version is bundled with mobile apps
/// Since v3.35.0 (iOS 15) we can use RETURNING clause
/// So although we able to embed custom SQLite,
/// for now we're forced to use last_insert_rowid to obtain id of the row after INSERT
/// https://www.sqlite.org/draft/lang_returning.html
/// https://github.com/yapstudios/YapDatabase/wiki/SQLite-version-(bundled-with-OS)
/// https://developer.android.com/reference/android/database/sqlite/package-summary.html

///
/// Common methods
///
no_arg_sql_function!(
    last_insert_rowid,
    diesel::sql_types::Integer,
    "Represents the SQL last_insert_row() function"
);

pub fn last_insert_id(context: &ManagedContext) -> QueryResult<i32> {
    diesel::select(last_insert_rowid)
        .get_result::<i32>(context.pool())
}

pub trait EntityUpdates<T> {
    type ResultType;
    fn append(self, t: T) -> Self::ResultType;
}

impl<T> EntityUpdates<T> for () {
    type ResultType = (T,);

    fn append(self, t: T) -> Self::ResultType {
        (t,)
    }
}

macro_rules! impl_entity_update_append {
    (()) => {};
    (($t0:ident $(, $types:ident)*)) => {
        impl<$t0, $($types,)* T> EntityUpdates<T> for ($t0, $($types,)*) {
            type ResultType = ($t0, $($types,)* T,);

            fn append(self, t: T) -> Self::ResultType {
                let ($t0, $($types,)*) = self;
                ($t0, $($types,)* t,)
            }
        }
        impl_entity_update_append! { ($($types),*) }
    };
}

pub trait EntityConvertible {
    fn to_entity<T, U>(&self) -> U
        where
            T: Table,
            T::FromClause: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite>,
            U: Insertable<T>,
            U::Values: IValues;

    /// fill update predicate
    fn to_update_values<T, V>(&self) -> Box<dyn EntityUpdates<V>>
        where T: Table,
              V: AsChangeset<Target = T>;

    fn from_entity<T: Entity>(entity: T, context: &ManagedContext) -> QueryResult<Self>;
}

// pub trait ModelConvertible where Self: Entity {
//     type Item;
//     fn new_model<M>(&self) -> Self::Item;
// }

pub trait Entity {
    type ID: ExpressionMethods;
    type ChainId: ExpressionMethods;

    fn id(&self) -> i32;

    fn target<T>() -> T where T: Table + diesel::QuerySource, T::FromClause: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite>;

    fn all_columns<T>() -> () where T: Table + diesel::QuerySource, T::FromClause: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> {
        <T as Table>::all_columns()
    }

    fn get_by_id<T>(id: i32, context: &ManagedContext) -> QueryResult<Self> {
        Self::any(Self::ID.eq(id), context)
    }

    fn get_by_ids<T>(id: Vec<i32>, context: &ManagedContext) -> QueryResult<Self> {
        Self::read(Self::ID.eq_all(ids), context)
    }

    fn delete_itself(&self, context: &ManagedContext) -> QueryResult<usize> {
        Self::delete_by_id(self.id(), context)
    }

    fn delete_by_id<T>(id: i32, context: &ManagedContext) -> QueryResult<usize> {
        let source = Self::target().filter(Self::ID.eq(id));
        Self::delete(source, context)
    }

    fn delete_by_ids<T>(ids: Vec<i32>, context: &ManagedContext) -> QueryResult<usize> {
        let source = Self::target().filter(Self::ID.eq_all(ids));
        Self::delete(source, context)
    }


    fn create<T, U>(records: U, context: &ManagedContext) -> QueryResult<usize>
        where
            T: Table + diesel::QuerySource,
            T::FromClause: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite>,
            U: Insertable<T>,
            U::Values: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> + diesel::insertable::CanInsertInSingleQuery<diesel::sqlite::Sqlite> {
        diesel::insert_into(Self::target())
            .values(records)
            .execute(context.pool())
    }

    fn create_and_get<T, U>(records: U, context: &ManagedContext) -> QueryResult<Self>
        where
            T: Table + diesel::QuerySource,
            T::FromClause: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite>,
            U: Insertable<T>,
            U::Values: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> + diesel::insertable::CanInsertInSingleQuery<diesel::sqlite::Sqlite> {
            Self::create(records, context)
                .and_then(|id|
                    last_insert_id(context)
                        .and_then(|row_id|
                            Self::get_by_id(row_id, context)))
    }

    fn create_many<T, U>(records: U, context: &ManagedContext) -> QueryResult<Vec<Self>>
        where
            T: Table + diesel::QuerySource,
            T::FromClause: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite>,
            U: Insertable<T>,
            U::Values: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> + diesel::insertable::CanInsertInSingleQuery<diesel::sqlite::Sqlite> {
        diesel::insert_into(Self::target())
            .values(records)
            // todo: returning_clauses_for_sqlite_3_35
            .get_results(context.pool())
    }

    fn delete<T>(source: T, context: &ManagedContext) -> QueryResult<usize>
        where
            T: diesel::query_builder::IntoUpdateTarget + diesel::associations::HasTable,
            T::Table: diesel::query_builder::QueryId + diesel::QuerySource,
            T::WhereClause: diesel::query_builder::QueryId + diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite>,
            <T::Table as diesel::QuerySource>::FromClause: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> {
        diesel::delete(source)
            .execute(context.pool())
    }

    fn delete_by<P, T>(predicate: P, context: &ManagedContext) -> QueryResult<usize>
        where
            T: diesel::query_builder::IntoUpdateTarget + diesel::associations::HasTable,
            T::Table: diesel::query_builder::QueryId + diesel::QuerySource,
            T::WhereClause: diesel::query_builder::QueryId + diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite>,
            <T::Table as diesel::QuerySource>::FromClause: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> {
        let source = Self::target().filter(predicate);
        diesel::delete(source)
            .execute(context.pool())
    }

    fn delete_for_chain_type<T>(chain_type: ChainType, context: &ManagedContext) -> QueryResult<usize>
        where
            T: diesel::query_builder::IntoUpdateTarget + diesel::associations::HasTable,
            T::Table: diesel::query_builder::QueryId + diesel::QuerySource,
            T::WhereClause: diesel::query_builder::QueryId + diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite>,
            <T::Table as diesel::QuerySource>::FromClause: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain_entity| Self::delete_by(CHAIN_ID.eq(chain_entity.id), context))
    }

    fn delete_by_chain_id<T>(chain_id: i32, context: &ManagedContext) -> QueryResult<usize>
        where
            T: diesel::query_builder::IntoUpdateTarget + diesel::associations::HasTable,
            T::Table: diesel::query_builder::QueryId + diesel::QuerySource,
            T::WhereClause: diesel::query_builder::QueryId + diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite>,
            <T::Table as diesel::QuerySource>::FromClause: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> {
        Self::delete_by(CHAIN_ID.eq(chain_id), context)
    }

    fn select_row<T, U, V>() -> diesel::helper_types::Select<V, U>
        where
            U: Expression,
            V: methods::SelectDsl<U>,
            T: Table + methods::SelectDsl<U> + Table<AllColumns=U>,
            T::AllColumns: SelectableExpression<T> {
        //diesel::select(T::all_columns())
        Self::target().select(T::all_columns())
    }

    fn all<T, U>(context: &ManagedContext) -> QueryResult<Vec<Self>>
        where
            T: Table + diesel::QuerySource,
            T::AllColumns: SelectableExpression<T>,
            U: Expression {
        let target = Self::target();
        let selection = <T as Table>::all_columns();
        let selected = target.select(selection);
        selected.get_results(context.pool())
    }

    fn read<P, T, U>(predicate: P, context: &ManagedContext) -> QueryResult<Vec<Self>>
        where
            T: Table + diesel::QuerySource,
            T::AllColumns: SelectableExpression<T>,
            U: Expression {
        let target = Self::target();
        let selection = <T as Table>::all_columns();
        let selected = target.select(selection);
        let filtered = selected.filter(predicate);
        filtered.get_results(context.pool())
    }

    fn any<P, T, U>(predicate: P, context: &ManagedContext) -> QueryResult<Self>
        where
            T: Table + diesel::QuerySource,
            T::AllColumns: SelectableExpression<T>,
            U: Expression {
        let selection = <T as Table>::all_columns();
        let selected = Self::target().select(selection);
        let filtered = selected.filter(predicate);
        filtered.first::<U>(context.pool())
    }

    fn count<P, U>(predicate: P, context: &ManagedContext) -> QueryResult<i64>
        where U: Expression {
        let selected = Self::target().select(count(predicate));
        selected.first::<U>(context.pool())
    }

    fn update<P, T, V>(predicate: P, values: V, context: &ManagedContext) -> QueryResult<usize>
        where T: Table,
              V: AsChangeset<Target = T> {
        let source = Self::target().filter(predicate);
        diesel::update(source)
            .set(values)
            .execute(context.pool())
    }

    /// update by entity.id
    fn update_with<T, V>(&self, values: V, context: &ManagedContext) -> QueryResult<usize>
        where T: Table,
              V: AsChangeset<Target = T> {
        Self::update(ID.eq(self.id()), &values, context)
    }
}
