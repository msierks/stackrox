// Code generated by pg-bindings generator. DO NOT EDIT.

package postgres

import (
	"context"
<<<<<<< HEAD
	"reflect"
=======
	"fmt"
>>>>>>> c95a9b179 (WIP)
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/stackrox/rox/central/globaldb"
	"github.com/stackrox/rox/central/metrics"
	"github.com/stackrox/rox/generated/storage"
	ops "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	"github.com/stackrox/rox/pkg/postgres/walker"
)

const (
	baseTable  = "reportconfigs"
	countStmt  = "SELECT COUNT(*) FROM reportconfigs"
	existsStmt = "SELECT EXISTS(SELECT 1 FROM reportconfigs WHERE Id = $1)"

	getStmt     = "SELECT serialized FROM reportconfigs WHERE Id = $1"
	deleteStmt  = "DELETE FROM reportconfigs WHERE Id = $1"
	walkStmt    = "SELECT serialized FROM reportconfigs"
	getIDsStmt  = "SELECT Id FROM reportconfigs"
	getManyStmt = "SELECT serialized FROM reportconfigs WHERE Id = ANY($1::text[])"

	deleteManyStmt = "DELETE FROM reportconfigs WHERE Id = ANY($1::text[])"
)

var (
	schema = walker.Walk(reflect.TypeOf((*storage.ReportConfiguration)(nil)), baseTable)
)

func init() {
	globaldb.RegisterTable(schema)
}

type Store interface {
	Count(ctx context.Context) (int, error)
	Exists(ctx context.Context, id string) (bool, error)
	Get(ctx context.Context, id string) (*storage.ReportConfiguration, bool, error)
	Upsert(ctx context.Context, obj *storage.ReportConfiguration) error
	UpsertMany(ctx context.Context, objs []*storage.ReportConfiguration) error
	Delete(ctx context.Context, id string) error
	GetIDs(ctx context.Context) ([]string, error)
	GetMany(ctx context.Context, ids []string) ([]*storage.ReportConfiguration, []int, error)
	DeleteMany(ctx context.Context, ids []string) error

	Walk(ctx context.Context, fn func(obj *storage.ReportConfiguration) error) error

	AckKeysIndexed(ctx context.Context, keys ...string) error
	GetKeysToIndex(ctx context.Context) ([]string, error)
}

type storeImpl struct {
	db *pgxpool.Pool
}

func createTableReportconfigs(ctx context.Context, db *pgxpool.Pool) {
	table := `
create table if not exists reportconfigs (
    Id varchar,
    Name varchar,
    Description varchar,
    Type integer,
    VulnReportFilters_Fixability integer,
    VulnReportFilters_SinceLastReport bool,
    VulnReportFilters_Severities int[],
    ScopeId varchar,
    EmailConfig_NotifierId varchar,
    EmailConfig_MailingLists text[],
    Schedule_IntervalType integer,
    Schedule_Hour integer,
    Schedule_Minute integer,
    Schedule_Weekly_Day integer,
    Schedule_DaysOfWeek_Days int[],
    Schedule_DaysOfMonth_Days int[],
    LastRunStatus_ReportStatus integer,
    LastRunStatus_LastRunTime timestamp,
    LastRunStatus_ErrorMsg varchar,
    LastSuccessfulRunTime timestamp,
    serialized bytea,
    PRIMARY KEY(Id)
)
`

	_, err := db.Exec(ctx, table)
	if err != nil {
		panic(fmt.Sprintf("error creating table %s: %v", table, err))
	}

	indexes := []string{}
	for _, index := range indexes {
		if _, err := db.Exec(ctx, index); err != nil {
			panic(err)
		}
	}

}

func insertIntoReportconfigs(ctx context.Context, tx pgx.Tx, obj *storage.ReportConfiguration) error {

	serialized, marshalErr := obj.Marshal()
	if marshalErr != nil {
		return marshalErr
	}

	values := []interface{}{
		// parent primary keys start
		obj.GetId(),
		obj.GetName(),
		obj.GetDescription(),
		obj.GetType(),
		obj.GetVulnReportFilters().GetFixability(),
		obj.GetVulnReportFilters().GetSinceLastReport(),
		obj.GetVulnReportFilters().GetSeverities(),
		obj.GetScopeId(),
		obj.GetEmailConfig().GetNotifierId(),
		obj.GetEmailConfig().GetMailingLists(),
		obj.GetSchedule().GetIntervalType(),
		obj.GetSchedule().GetHour(),
		obj.GetSchedule().GetMinute(),
		obj.GetSchedule().GetWeekly().GetDay(),
		obj.GetSchedule().GetDaysOfWeek().GetDays(),
		obj.GetSchedule().GetDaysOfMonth().GetDays(),
		obj.GetLastRunStatus().GetReportStatus(),
		pgutils.NilOrStringTimestamp(obj.GetLastRunStatus().GetLastRunTime()),
		obj.GetLastRunStatus().GetErrorMsg(),
		pgutils.NilOrStringTimestamp(obj.GetLastSuccessfulRunTime()),
		serialized,
	}

	finalStr := "INSERT INTO reportconfigs (Id, Name, Description, Type, VulnReportFilters_Fixability, VulnReportFilters_SinceLastReport, VulnReportFilters_Severities, ScopeId, EmailConfig_NotifierId, EmailConfig_MailingLists, Schedule_IntervalType, Schedule_Hour, Schedule_Minute, Schedule_Weekly_Day, Schedule_DaysOfWeek_Days, Schedule_DaysOfMonth_Days, LastRunStatus_ReportStatus, LastRunStatus_LastRunTime, LastRunStatus_ErrorMsg, LastSuccessfulRunTime, serialized) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21) ON CONFLICT(Id) DO UPDATE SET Id = EXCLUDED.Id, Name = EXCLUDED.Name, Description = EXCLUDED.Description, Type = EXCLUDED.Type, VulnReportFilters_Fixability = EXCLUDED.VulnReportFilters_Fixability, VulnReportFilters_SinceLastReport = EXCLUDED.VulnReportFilters_SinceLastReport, VulnReportFilters_Severities = EXCLUDED.VulnReportFilters_Severities, ScopeId = EXCLUDED.ScopeId, EmailConfig_NotifierId = EXCLUDED.EmailConfig_NotifierId, EmailConfig_MailingLists = EXCLUDED.EmailConfig_MailingLists, Schedule_IntervalType = EXCLUDED.Schedule_IntervalType, Schedule_Hour = EXCLUDED.Schedule_Hour, Schedule_Minute = EXCLUDED.Schedule_Minute, Schedule_Weekly_Day = EXCLUDED.Schedule_Weekly_Day, Schedule_DaysOfWeek_Days = EXCLUDED.Schedule_DaysOfWeek_Days, Schedule_DaysOfMonth_Days = EXCLUDED.Schedule_DaysOfMonth_Days, LastRunStatus_ReportStatus = EXCLUDED.LastRunStatus_ReportStatus, LastRunStatus_LastRunTime = EXCLUDED.LastRunStatus_LastRunTime, LastRunStatus_ErrorMsg = EXCLUDED.LastRunStatus_ErrorMsg, LastSuccessfulRunTime = EXCLUDED.LastSuccessfulRunTime, serialized = EXCLUDED.serialized"
	_, err := tx.Exec(ctx, finalStr, values...)
	if err != nil {
		return err
	}

	return nil
}

// New returns a new Store instance using the provided sql instance.
func New(ctx context.Context, db *pgxpool.Pool) Store {
	createTableReportconfigs(ctx, db)

	return &storeImpl{
		db: db,
	}
}

func (s *storeImpl) upsert(ctx context.Context, objs ...*storage.ReportConfiguration) error {
	conn, release := s.acquireConn(ctx, ops.Get, "ReportConfiguration")
	defer release()

	for _, obj := range objs {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}

		if err := insertIntoReportconfigs(ctx, tx, obj); err != nil {
			if err := tx.Rollback(ctx); err != nil {
				return err
			}
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *storeImpl) Upsert(ctx context.Context, obj *storage.ReportConfiguration) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Upsert, "ReportConfiguration")

	return s.upsert(ctx, obj)
}

func (s *storeImpl) UpsertMany(ctx context.Context, objs []*storage.ReportConfiguration) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.UpdateMany, "ReportConfiguration")

	return s.upsert(ctx, objs...)
}

// Count returns the number of objects in the store
func (s *storeImpl) Count(ctx context.Context) (int, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Count, "ReportConfiguration")

	row := s.db.QueryRow(ctx, countStmt)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// Exists returns if the id exists in the store
func (s *storeImpl) Exists(ctx context.Context, id string) (bool, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Exists, "ReportConfiguration")

	row := s.db.QueryRow(ctx, existsStmt, id)
	var exists bool
	if err := row.Scan(&exists); err != nil {
		return false, pgutils.ErrNilIfNoRows(err)
	}
	return exists, nil
}

// Get returns the object, if it exists from the store
func (s *storeImpl) Get(ctx context.Context, id string) (*storage.ReportConfiguration, bool, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Get, "ReportConfiguration")

	conn, release := s.acquireConn(ctx, ops.Get, "ReportConfiguration")
	defer release()

	row := conn.QueryRow(ctx, getStmt, id)
	var data []byte
	if err := row.Scan(&data); err != nil {
		return nil, false, pgutils.ErrNilIfNoRows(err)
	}

	var msg storage.ReportConfiguration
	if err := proto.Unmarshal(data, &msg); err != nil {
		return nil, false, err
	}
	return &msg, true, nil
}

func (s *storeImpl) acquireConn(ctx context.Context, op ops.Op, typ string) (*pgxpool.Conn, func()) {
	defer metrics.SetAcquireDBConnDuration(time.Now(), op, typ)
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		panic(err)
	}
	return conn, conn.Release
}

// Delete removes the specified ID from the store
func (s *storeImpl) Delete(ctx context.Context, id string) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Remove, "ReportConfiguration")

	conn, release := s.acquireConn(ctx, ops.Remove, "ReportConfiguration")
	defer release()

	if _, err := conn.Exec(ctx, deleteStmt, id); err != nil {
		return err
	}
	return nil
}

// GetIDs returns all the IDs for the store
func (s *storeImpl) GetIDs(ctx context.Context) ([]string, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.GetAll, "storage.ReportConfigurationIDs")

	rows, err := s.db.Query(ctx, getIDsStmt)
	if err != nil {
		return nil, pgutils.ErrNilIfNoRows(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// GetMany returns the objects specified by the IDs or the index in the missing indices slice
func (s *storeImpl) GetMany(ctx context.Context, ids []string) ([]*storage.ReportConfiguration, []int, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.GetMany, "ReportConfiguration")

	conn, release := s.acquireConn(ctx, ops.GetMany, "ReportConfiguration")
	defer release()

	rows, err := conn.Query(ctx, getManyStmt, ids)
	if err != nil {
		if err == pgx.ErrNoRows {
			missingIndices := make([]int, 0, len(ids))
			for i := range ids {
				missingIndices = append(missingIndices, i)
			}
			return nil, missingIndices, nil
		}
		return nil, nil, err
	}
	defer rows.Close()
	resultsByID := make(map[string]*storage.ReportConfiguration)
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, nil, err
		}
		msg := &storage.ReportConfiguration{}
		if err := proto.Unmarshal(data, msg); err != nil {
			return nil, nil, err
		}
		resultsByID[msg.GetId()] = msg
	}
	missingIndices := make([]int, 0, len(ids)-len(resultsByID))
	// It is important that the elems are populated in the same order as the input ids
	// slice, since some calling code relies on that to maintain order.
	elems := make([]*storage.ReportConfiguration, 0, len(resultsByID))
	for i, id := range ids {
		if result, ok := resultsByID[id]; !ok {
			missingIndices = append(missingIndices, i)
		} else {
			elems = append(elems, result)
		}
	}
	return elems, missingIndices, nil
}

// Delete removes the specified IDs from the store
func (s *storeImpl) DeleteMany(ctx context.Context, ids []string) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.RemoveMany, "ReportConfiguration")

	conn, release := s.acquireConn(ctx, ops.RemoveMany, "ReportConfiguration")
	defer release()
	if _, err := conn.Exec(ctx, deleteManyStmt, ids); err != nil {
		return err
	}
	return nil
}

// Walk iterates over all of the objects in the store and applies the closure
func (s *storeImpl) Walk(ctx context.Context, fn func(obj *storage.ReportConfiguration) error) error {
	rows, err := s.db.Query(ctx, walkStmt)
	if err != nil {
		return pgutils.ErrNilIfNoRows(err)
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return err
		}
		var msg storage.ReportConfiguration
		if err := proto.Unmarshal(data, &msg); err != nil {
			return err
		}
		if err := fn(&msg); err != nil {
			return err
		}
	}
	return nil
}

//// Used for testing

func dropTableReportconfigs(ctx context.Context, db *pgxpool.Pool) {
	_, _ = db.Exec(ctx, "DROP TABLE IF EXISTS reportconfigs CASCADE")

}

func Destroy(ctx context.Context, db *pgxpool.Pool) {
	dropTableReportconfigs(ctx, db)
}

//// Stubs for satisfying legacy interfaces

// AckKeysIndexed acknowledges the passed keys were indexed
func (s *storeImpl) AckKeysIndexed(ctx context.Context, keys ...string) error {
	return nil
}

// GetKeysToIndex returns the keys that need to be indexed
func (s *storeImpl) GetKeysToIndex(ctx context.Context) ([]string, error) {
	return nil, nil
}
