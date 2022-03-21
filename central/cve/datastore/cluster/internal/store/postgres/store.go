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
	baseTable  = "cluster_cves"
	countStmt  = "SELECT COUNT(*) FROM cluster_cves"
	existsStmt = "SELECT EXISTS(SELECT 1 FROM cluster_cves WHERE Id = $1)"

	getStmt     = "SELECT serialized FROM cluster_cves WHERE Id = $1"
	deleteStmt  = "DELETE FROM cluster_cves WHERE Id = $1"
	walkStmt    = "SELECT serialized FROM cluster_cves"
	getIDsStmt  = "SELECT Id FROM cluster_cves"
	getManyStmt = "SELECT serialized FROM cluster_cves WHERE Id = ANY($1::text[])"

	deleteManyStmt = "DELETE FROM cluster_cves WHERE Id = ANY($1::text[])"
)

var (
	schema = walker.Walk(reflect.TypeOf((*storage.CVE)(nil)), baseTable)
)

func init() {
	globaldb.RegisterTable(schema)
}

type Store interface {
	Count(ctx context.Context) (int, error)
	Exists(ctx context.Context, id string) (bool, error)
	Get(ctx context.Context, id string) (*storage.CVE, bool, error)
	Upsert(ctx context.Context, obj *storage.CVE) error
	UpsertMany(ctx context.Context, objs []*storage.CVE) error
	Delete(ctx context.Context, id string) error
	GetIDs(ctx context.Context) ([]string, error)
	GetMany(ctx context.Context, ids []string) ([]*storage.CVE, []int, error)
	DeleteMany(ctx context.Context, ids []string) error

	Walk(ctx context.Context, fn func(obj *storage.CVE) error) error

	AckKeysIndexed(ctx context.Context, keys ...string) error
	GetKeysToIndex(ctx context.Context) ([]string, error)
}

type storeImpl struct {
	db *pgxpool.Pool
}

func createTableClusterCves(ctx context.Context, db *pgxpool.Pool) {
	table := `
create table if not exists cluster_cves (
    Id varchar,
    Cvss numeric,
    ImpactScore numeric,
    Summary varchar,
    Link varchar,
    PublishedOn timestamp,
    CreatedAt timestamp,
    LastModified timestamp,
    ScoreVersion integer,
    CvssV2_Vector varchar,
    CvssV2_AttackVector integer,
    CvssV2_AccessComplexity integer,
    CvssV2_Authentication integer,
    CvssV2_Confidentiality integer,
    CvssV2_Integrity integer,
    CvssV2_Availability integer,
    CvssV2_ExploitabilityScore numeric,
    CvssV2_ImpactScore numeric,
    CvssV2_Score numeric,
    CvssV2_Severity integer,
    CvssV3_Vector varchar,
    CvssV3_ExploitabilityScore numeric,
    CvssV3_ImpactScore numeric,
    CvssV3_AttackVector integer,
    CvssV3_AttackComplexity integer,
    CvssV3_PrivilegesRequired integer,
    CvssV3_UserInteraction integer,
    CvssV3_Scope integer,
    CvssV3_Confidentiality integer,
    CvssV3_Integrity integer,
    CvssV3_Availability integer,
    CvssV3_Score numeric,
    CvssV3_Severity integer,
    Suppressed bool,
    SuppressActivation timestamp,
    SuppressExpiry timestamp,
    Severity integer,
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

	createTableClusterCvesReferences(ctx, db)
}

func createTableClusterCvesReferences(ctx context.Context, db *pgxpool.Pool) {
	table := `
create table if not exists cluster_cves_References (
    cluster_cves_Id varchar,
    idx integer,
    URI varchar,
    Tags text[],
    PRIMARY KEY(cluster_cves_Id, idx),
    CONSTRAINT fk_parent_table FOREIGN KEY (cluster_cves_Id) REFERENCES cluster_cves(Id) ON DELETE CASCADE
)
`

	_, err := db.Exec(ctx, table)
	if err != nil {
		panic(fmt.Sprintf("error creating table %s: %v", table, err))
	}

	indexes := []string{

		"create index if not exists clusterCvesReferences_idx on cluster_cves_References using btree(idx)",
	}
	for _, index := range indexes {
		if _, err := db.Exec(ctx, index); err != nil {
			panic(err)
		}
	}

}

func insertIntoClusterCves(ctx context.Context, tx pgx.Tx, obj *storage.CVE) error {

	serialized, marshalErr := obj.Marshal()
	if marshalErr != nil {
		return marshalErr
	}

	values := []interface{}{
		// parent primary keys start
		obj.GetId(),
		obj.GetCvss(),
		obj.GetImpactScore(),
		obj.GetSummary(),
		obj.GetLink(),
		pgutils.NilOrStringTimestamp(obj.GetPublishedOn()),
		pgutils.NilOrStringTimestamp(obj.GetCreatedAt()),
		pgutils.NilOrStringTimestamp(obj.GetLastModified()),
		obj.GetScoreVersion(),
		obj.GetCvssV2().GetVector(),
		obj.GetCvssV2().GetAttackVector(),
		obj.GetCvssV2().GetAccessComplexity(),
		obj.GetCvssV2().GetAuthentication(),
		obj.GetCvssV2().GetConfidentiality(),
		obj.GetCvssV2().GetIntegrity(),
		obj.GetCvssV2().GetAvailability(),
		obj.GetCvssV2().GetExploitabilityScore(),
		obj.GetCvssV2().GetImpactScore(),
		obj.GetCvssV2().GetScore(),
		obj.GetCvssV2().GetSeverity(),
		obj.GetCvssV3().GetVector(),
		obj.GetCvssV3().GetExploitabilityScore(),
		obj.GetCvssV3().GetImpactScore(),
		obj.GetCvssV3().GetAttackVector(),
		obj.GetCvssV3().GetAttackComplexity(),
		obj.GetCvssV3().GetPrivilegesRequired(),
		obj.GetCvssV3().GetUserInteraction(),
		obj.GetCvssV3().GetScope(),
		obj.GetCvssV3().GetConfidentiality(),
		obj.GetCvssV3().GetIntegrity(),
		obj.GetCvssV3().GetAvailability(),
		obj.GetCvssV3().GetScore(),
		obj.GetCvssV3().GetSeverity(),
		obj.GetSuppressed(),
		pgutils.NilOrStringTimestamp(obj.GetSuppressActivation()),
		pgutils.NilOrStringTimestamp(obj.GetSuppressExpiry()),
		obj.GetSeverity(),
		serialized,
	}

	finalStr := "INSERT INTO cluster_cves (Id, Cvss, ImpactScore, Summary, Link, PublishedOn, CreatedAt, LastModified, ScoreVersion, CvssV2_Vector, CvssV2_AttackVector, CvssV2_AccessComplexity, CvssV2_Authentication, CvssV2_Confidentiality, CvssV2_Integrity, CvssV2_Availability, CvssV2_ExploitabilityScore, CvssV2_ImpactScore, CvssV2_Score, CvssV2_Severity, CvssV3_Vector, CvssV3_ExploitabilityScore, CvssV3_ImpactScore, CvssV3_AttackVector, CvssV3_AttackComplexity, CvssV3_PrivilegesRequired, CvssV3_UserInteraction, CvssV3_Scope, CvssV3_Confidentiality, CvssV3_Integrity, CvssV3_Availability, CvssV3_Score, CvssV3_Severity, Suppressed, SuppressActivation, SuppressExpiry, Severity, serialized) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38) ON CONFLICT(Id) DO UPDATE SET Id = EXCLUDED.Id, Cvss = EXCLUDED.Cvss, ImpactScore = EXCLUDED.ImpactScore, Summary = EXCLUDED.Summary, Link = EXCLUDED.Link, PublishedOn = EXCLUDED.PublishedOn, CreatedAt = EXCLUDED.CreatedAt, LastModified = EXCLUDED.LastModified, ScoreVersion = EXCLUDED.ScoreVersion, CvssV2_Vector = EXCLUDED.CvssV2_Vector, CvssV2_AttackVector = EXCLUDED.CvssV2_AttackVector, CvssV2_AccessComplexity = EXCLUDED.CvssV2_AccessComplexity, CvssV2_Authentication = EXCLUDED.CvssV2_Authentication, CvssV2_Confidentiality = EXCLUDED.CvssV2_Confidentiality, CvssV2_Integrity = EXCLUDED.CvssV2_Integrity, CvssV2_Availability = EXCLUDED.CvssV2_Availability, CvssV2_ExploitabilityScore = EXCLUDED.CvssV2_ExploitabilityScore, CvssV2_ImpactScore = EXCLUDED.CvssV2_ImpactScore, CvssV2_Score = EXCLUDED.CvssV2_Score, CvssV2_Severity = EXCLUDED.CvssV2_Severity, CvssV3_Vector = EXCLUDED.CvssV3_Vector, CvssV3_ExploitabilityScore = EXCLUDED.CvssV3_ExploitabilityScore, CvssV3_ImpactScore = EXCLUDED.CvssV3_ImpactScore, CvssV3_AttackVector = EXCLUDED.CvssV3_AttackVector, CvssV3_AttackComplexity = EXCLUDED.CvssV3_AttackComplexity, CvssV3_PrivilegesRequired = EXCLUDED.CvssV3_PrivilegesRequired, CvssV3_UserInteraction = EXCLUDED.CvssV3_UserInteraction, CvssV3_Scope = EXCLUDED.CvssV3_Scope, CvssV3_Confidentiality = EXCLUDED.CvssV3_Confidentiality, CvssV3_Integrity = EXCLUDED.CvssV3_Integrity, CvssV3_Availability = EXCLUDED.CvssV3_Availability, CvssV3_Score = EXCLUDED.CvssV3_Score, CvssV3_Severity = EXCLUDED.CvssV3_Severity, Suppressed = EXCLUDED.Suppressed, SuppressActivation = EXCLUDED.SuppressActivation, SuppressExpiry = EXCLUDED.SuppressExpiry, Severity = EXCLUDED.Severity, serialized = EXCLUDED.serialized"
	_, err := tx.Exec(ctx, finalStr, values...)
	if err != nil {
		return err
	}

	var query string

	for childIdx, child := range obj.GetReferences() {
		if err := insertIntoClusterCvesReferences(ctx, tx, child, obj.GetId(), childIdx); err != nil {
			return err
		}
	}

	query = "delete from cluster_cves_References where cluster_cves_Id = $1 AND idx >= $2"
	_, err = tx.Exec(ctx, query, obj.GetId(), len(obj.GetReferences()))
	if err != nil {
		return err
	}
	return nil
}

func insertIntoClusterCvesReferences(ctx context.Context, tx pgx.Tx, obj *storage.CVE_Reference, cluster_cves_Id string, idx int) error {

	values := []interface{}{
		// parent primary keys start
		cluster_cves_Id,
		idx,
		obj.GetURI(),
		obj.GetTags(),
	}

	finalStr := "INSERT INTO cluster_cves_References (cluster_cves_Id, idx, URI, Tags) VALUES($1, $2, $3, $4) ON CONFLICT(cluster_cves_Id, idx) DO UPDATE SET cluster_cves_Id = EXCLUDED.cluster_cves_Id, idx = EXCLUDED.idx, URI = EXCLUDED.URI, Tags = EXCLUDED.Tags"
	_, err := tx.Exec(ctx, finalStr, values...)
	if err != nil {
		return err
	}

	return nil
}

// New returns a new Store instance using the provided sql instance.
func New(ctx context.Context, db *pgxpool.Pool) Store {
	createTableClusterCves(ctx, db)

	return &storeImpl{
		db: db,
	}
}

func (s *storeImpl) upsert(ctx context.Context, objs ...*storage.CVE) error {
	conn, release := s.acquireConn(ctx, ops.Get, "CVE")
	defer release()

	for _, obj := range objs {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}

		if err := insertIntoClusterCves(ctx, tx, obj); err != nil {
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

func (s *storeImpl) Upsert(ctx context.Context, obj *storage.CVE) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Upsert, "CVE")

	return s.upsert(ctx, obj)
}

func (s *storeImpl) UpsertMany(ctx context.Context, objs []*storage.CVE) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.UpdateMany, "CVE")

	return s.upsert(ctx, objs...)
}

// Count returns the number of objects in the store
func (s *storeImpl) Count(ctx context.Context) (int, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Count, "CVE")

	row := s.db.QueryRow(ctx, countStmt)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// Exists returns if the id exists in the store
func (s *storeImpl) Exists(ctx context.Context, id string) (bool, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Exists, "CVE")

	row := s.db.QueryRow(ctx, existsStmt, id)
	var exists bool
	if err := row.Scan(&exists); err != nil {
		return false, pgutils.ErrNilIfNoRows(err)
	}
	return exists, nil
}

// Get returns the object, if it exists from the store
func (s *storeImpl) Get(ctx context.Context, id string) (*storage.CVE, bool, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Get, "CVE")

	conn, release := s.acquireConn(ctx, ops.Get, "CVE")
	defer release()

	row := conn.QueryRow(ctx, getStmt, id)
	var data []byte
	if err := row.Scan(&data); err != nil {
		return nil, false, pgutils.ErrNilIfNoRows(err)
	}

	var msg storage.CVE
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
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Remove, "CVE")

	conn, release := s.acquireConn(ctx, ops.Remove, "CVE")
	defer release()

	if _, err := conn.Exec(ctx, deleteStmt, id); err != nil {
		return err
	}
	return nil
}

// GetIDs returns all the IDs for the store
func (s *storeImpl) GetIDs(ctx context.Context) ([]string, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.GetAll, "storage.CVEIDs")

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
func (s *storeImpl) GetMany(ctx context.Context, ids []string) ([]*storage.CVE, []int, error) {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.GetMany, "CVE")

	conn, release := s.acquireConn(ctx, ops.GetMany, "CVE")
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
	resultsByID := make(map[string]*storage.CVE)
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, nil, err
		}
		msg := &storage.CVE{}
		if err := proto.Unmarshal(data, msg); err != nil {
			return nil, nil, err
		}
		resultsByID[msg.GetId()] = msg
	}
	missingIndices := make([]int, 0, len(ids)-len(resultsByID))
	// It is important that the elems are populated in the same order as the input ids
	// slice, since some calling code relies on that to maintain order.
	elems := make([]*storage.CVE, 0, len(resultsByID))
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
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.RemoveMany, "CVE")

	conn, release := s.acquireConn(ctx, ops.RemoveMany, "CVE")
	defer release()
	if _, err := conn.Exec(ctx, deleteManyStmt, ids); err != nil {
		return err
	}
	return nil
}

// Walk iterates over all of the objects in the store and applies the closure
func (s *storeImpl) Walk(ctx context.Context, fn func(obj *storage.CVE) error) error {
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
		var msg storage.CVE
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

func dropTableClusterCves(ctx context.Context, db *pgxpool.Pool) {
	_, _ = db.Exec(ctx, "DROP TABLE IF EXISTS cluster_cves CASCADE")
	dropTableClusterCvesReferences(ctx, db)

}

func dropTableClusterCvesReferences(ctx context.Context, db *pgxpool.Pool) {
	_, _ = db.Exec(ctx, "DROP TABLE IF EXISTS cluster_cves_References CASCADE")

}

func Destroy(ctx context.Context, db *pgxpool.Pool) {
	dropTableClusterCves(ctx, db)
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
