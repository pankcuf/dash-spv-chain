use diesel::{Expression, ExpressionMethods, Insertable, QueryDsl, QueryResult, QuerySource, RunQueryDsl, SelectableExpression, Table};
use diesel::associations::HasTable;
use diesel::dsl::count;
use diesel::insertable::CanInsertInSingleQuery;
use diesel::query_builder::{AsChangeset, AsQuery, IntoUpdateTarget, QueryFragment, QueryId, UpdateStatement};
use diesel::query_dsl::methods::SelectDsl;
use diesel::sql_types::SingleValue;
use diesel::sqlite::Sqlite;
use crate::chain::common::ChainType;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
// It's interesting to know which SQLite version is bundled with mobile apps
// Since v3.35.0 (iOS 15) we can use RETURNING clause
// So although we able to embed custom SQLite,
// for now we're forced to use last_insert_rowid to obtain id of the row after INSERT
// https://www.sqlite.org/draft/lang_returning.html
// https://github.com/yapstudios/YapDatabase/wiki/SQLite-version-(bundled-with-OS)
// https://developer.android.com/reference/android/database/sqlite/package-summary.html

sql_function!{
    /// Represents the SQL last_insert_row() function
    fn last_insert_rowid() -> diesel::sql_types::Integer;
}
pub fn last_insert_id(context: &ManagedContext) -> QueryResult<i32> {
    diesel::select(last_insert_rowid())
        .get_result::<i32>(&mut context.connection())
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

#[allow(unused_macros)]
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

// pub trait EntityConvertible {
//     fn to_entity<T, U>(&self) -> U
//         where
//             T: Table,
//             T::FromClause: QueryFragment<Sqlite>,
//             U: Insertable<T>,
//             U::Values: QueryFragment<Sqlite> + CanInsertInSingleQuery<Sqlite>;
//
//     /// fill update predicate
//     fn to_update_values(&self) -> Box<dyn EntityUpdates<bool, ResultType = (bool, )>>;
//
//     fn from_entity<T: Entity>(entity: T, context: &ManagedContext) -> QueryResult<Self> where Self: Sized;
// }

pub trait Entity {
    type ID: ExpressionMethods;
    //type ChainId: ExpressionMethods;

    fn id(&self) -> i32;

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite>;

    fn all_columns<T>() -> () where T: Table<AllColumns = ()> + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        <T as Table>::all_columns()
    }

    fn get_by_id(id: i32, context: &ManagedContext) -> QueryResult<Self> where Self: Sized {
        Self::any(Self::ID.eq(id), context)
    }

    fn get_by_ids<T>(ids: Vec<i32>, context: &ManagedContext) -> QueryResult<Vec<Self>>
        where Self: Sized {
        Self::read(Self::ID.eq_all(ids), context)
    }

    fn delete_by_id<T>(id: i32, context: &ManagedContext) -> QueryResult<usize>
        where
            T: Table + QuerySource,
            <T as AsQuery>::Query: Table,
            <T as QuerySource>::FromClause: QueryFragment<Sqlite> {
        let source = Self::target::<T>().filter(Self::ID.eq(id));
        Self::delete(source, context)
    }

    fn delete_by_ids<T>(ids: Vec<i32>, context: &ManagedContext) -> QueryResult<usize>
        where T: Table + QuerySource,
              <T as AsQuery>::Query: Table,
              <T as QuerySource>::FromClause: QueryFragment<Sqlite> {
        let source = Self::target::<T>().filter(Self::ID.eq_all(ids));
        Self::delete(source, context)
    }


    fn create<T, U>(records: U, context: &ManagedContext) -> QueryResult<usize>
        where
            T: Table + QuerySource + QueryId,
            T::FromClause: QueryFragment<Sqlite>,
            U: Insertable<T>,
            U::Values: QueryFragment<Sqlite> + CanInsertInSingleQuery<Sqlite>,
            <U as Insertable<T>>::Values: QueryId {
        diesel::insert_into(Self::target())
            .values(records)
            .execute(&mut context.connection())
    }

    fn create_and_get<T, U>(records: U, context: &ManagedContext) -> QueryResult<Self>
        where
            Self: Sized,
            T: Table + QuerySource + QueryId,
            T::FromClause: QueryFragment<Sqlite>,
            U: Insertable<T>,
            U::Values: QueryFragment<Sqlite> + CanInsertInSingleQuery<Sqlite>,
            <U as Insertable<T>>::Values: QueryId {
            Self::create(records, context)
                .and_then(|id|
                    last_insert_id(context)
                        .and_then(|row_id|
                            Self::get_by_id(row_id, context)))
    }

    fn create_many<T, U>(records: U, context: &ManagedContext) -> QueryResult<Vec<Self>>
        where
            Self: Sized,
            T: Table + QuerySource,
            T::FromClause: QueryFragment<Sqlite>,
            U: Insertable<T>,
            U::Values: QueryFragment<Sqlite> + CanInsertInSingleQuery<Sqlite> {
        let target = Self::target::<T>();
        diesel::insert_into(target)
            .values(records)
            // todo: returning_clauses_for_sqlite_3_35
            .get_results(&mut context.connection())
    }

    fn delete<T>(source: T, context: &ManagedContext) -> QueryResult<usize>
        where
            T: IntoUpdateTarget + HasTable,
            T::Table: QueryId + QuerySource,
            T::WhereClause: QueryId + QueryFragment<Sqlite>,
            <T::Table as QuerySource>::FromClause: QueryFragment<Sqlite> {
        diesel::delete(source)
            .execute(&mut context.connection())
    }

    fn delete_by<P, T>(predicate: P, context: &ManagedContext) -> QueryResult<usize>
        where
            T: Table + IntoUpdateTarget + HasTable + QuerySource + AsQuery,
            T::Table: QueryId + QuerySource,
            T::WhereClause: QueryId + QueryFragment<Sqlite>,
            <T::Table as QuerySource>::FromClause: QueryFragment<Sqlite>,
            <T as AsQuery>::Query: Table,
            <T as QuerySource>::FromClause: QueryFragment<Sqlite> {
        let source = Self::target::<T>().filter(predicate);
        diesel::delete(source)
            .execute(&mut context.connection())
    }

    fn delete_for_chain_type<T>(chain_type: ChainType, context: &ManagedContext) -> QueryResult<usize>
        where
            T: IntoUpdateTarget + HasTable,
            T::Table: QueryId + QuerySource,
            T::WhereClause: QueryId + QueryFragment<Sqlite>,
            <T::Table as QuerySource>::FromClause: QueryFragment<Sqlite> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain_entity| Self::delete_by(Self::CHAIN_ID.eq(chain_entity.id), context))
    }

    fn delete_by_chain_id<T>(chain_id: i32, context: &ManagedContext) -> QueryResult<usize>
        where
            T: IntoUpdateTarget + HasTable,
            T::Table: QueryId + QuerySource,
            T::WhereClause: QueryId + QueryFragment<Sqlite>,
            <T::Table as QuerySource>::FromClause: QueryFragment<Sqlite> {
        Self::delete_by(Self::CHAIN_ID.eq(chain_id), context)
    }

    // fn select_row<T, U, V>() -> diesel::helper_types::Select<V, U>
    //     where
    //         U: Expression,
    //         V: SelectDsl<U>,
    //         T: Table + SelectDsl<U> + Table<AllColumns=U>,
    //         T::AllColumns: SelectableExpression<T>,
    //         <T as QuerySource>::FromClause: QueryFragment<Sqlite> {
    //     //diesel::select(T::all_columns())
    //     Self::target::<V>().select(T::all_columns())
    // }

    fn all<T, U>(context: &ManagedContext) -> QueryResult<Vec<Self>>
        where
            Self: Sized,
            T: Table + QuerySource,
            T::AllColumns: SelectableExpression<T>,
            U: Expression,
            <T as AsQuery>::Query: Table,
            <T as QuerySource>::FromClause: QueryFragment<Sqlite> {
        let target = Self::target::<T>();
        let selection = <T as Table>::all_columns();
        let selected = target.select(selection);
        selected.get_results(&mut context.connection())
    }

    fn read<P, T, U>(predicate: P, context: &ManagedContext) -> QueryResult<Vec<Self>>
        where
            Self: Sized,
            T: Table + QuerySource,
            T::AllColumns: SelectableExpression<T>,
            U: Expression,
            <T as AsQuery>::Query: Table,
            <T as QuerySource>::FromClause: QueryFragment<Sqlite> {
        let target = Self::target::<T>();
        let selection = <T as Table>::all_columns();
        let selected = target.select(selection);
        let filtered = selected.filter(predicate);
        filtered.get_results(&mut context.connection())
    }

    fn any<P, T, U>(predicate: P, context: &ManagedContext) -> QueryResult<Self>
        where
            Self: Sized,
            T: Table + QuerySource,
            T::AllColumns: SelectableExpression<T>,
            <T as AsQuery>::Query: Table,
            <T as QuerySource>::FromClause: QueryFragment<Sqlite>,
            U: Expression {
        let selection = <T as Table>::all_columns();
        let selected = Self::target::<T>().select(selection);
        let filtered = selected.filter(predicate);
        filtered.first::<U>(&mut context.connection())
    }

    fn count<P, T, U>(predicate: P, context: &ManagedContext) -> QueryResult<i64>
        where
            P: Expression,
            T: Table,
            U: Expression,
            <P as Expression>::SqlType: SingleValue,
            <T as QuerySource>::FromClause: QueryFragment<Sqlite>,
            <T as AsQuery>::Query: Table {
        let selected = Self::target::<T>().select(count(predicate));
        selected.first::<U>(&mut context.connection())
    }
    // V: changeset::AsChangeset<Target = T>,
    // UpdateStatement<T, U, V::Changeset>: AsQuery,

    fn update<P, T, U, V>(predicate: P, values: V, context: &ManagedContext) -> QueryResult<usize>
        where T: Table,
              V: AsChangeset<Target = T>,
              U: QueryFragment<Sqlite>,
              UpdateStatement<T, U, V::Changeset>: AsQuery,
              <T as AsQuery>::Query: Table,
              <T as QuerySource>::FromClause: QueryFragment<Sqlite>,
              <V as AsChangeset>::Changeset: QueryFragment<Sqlite> {
        let source = Self::target::<T>().filter(predicate);
        diesel::update(source)
            .set(values)
            .execute(&mut context.connection())
    }

    /// update by entity.id
    fn update_with<T, U, V>(&self, values: V, context: &ManagedContext) -> QueryResult<usize>
        where T: Table,
              V: AsChangeset<Target = T>,
              U: QueryFragment<Sqlite>,
              UpdateStatement<T, U, V::Changeset>: AsQuery,
              <T as AsQuery>::Query: Table,
              <T as QuerySource>::FromClause: QueryFragment<Sqlite>,
              <V as AsChangeset>::Changeset: QueryFragment<Sqlite> {
        Self::update(Self::ID.eq(self.id()), values, context)
    }
}
