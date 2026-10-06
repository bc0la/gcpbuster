package engagement

import (
	"context"
	"fmt"
	"time"

	"github.com/bc0la/gcpbuster/internal/findings"
)

// MaxFindingBatch bounds transaction size and serialization memory. Callers
// flush at this boundary rather than buffering a whole organization in memory.
const MaxFindingBatch = 256

const insertFindingSQL = `INSERT INTO findings(project_id, region, module, severity, resource_name, title, detail_json, raw_output_path, created_at)
 VALUES(?,?,?,?,?,?,?,?,?)`

// WriteBatch persists the entire batch in one transaction and one commit.
// Serialization, SQL, or cancellation errors leave no partial batch behind.
// This uses the engagement's existing durability and private-file settings.
func (e *Engagement) WriteBatch(ctx context.Context, batch []findings.Finding) error {
	if len(batch) > MaxFindingBatch {
		return fmt.Errorf("finding batch exceeds maximum of %d", MaxFindingBatch)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(batch) == 0 {
		return nil
	}
	type preparedFinding struct {
		detail  string
		created time.Time
	}
	prepared := make([]preparedFinding, len(batch))
	for i := range batch {
		if err := ctx.Err(); err != nil {
			return err
		}
		detail, err := batch[i].DetailJSON()
		if err != nil {
			return err
		}
		created := batch[i].CreatedAt
		if created.IsZero() {
			created = time.Now().UTC()
		}
		prepared[i] = preparedFinding{detail, created}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, insertFindingSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i, f := range batch {
		if _, err := stmt.ExecContext(ctx, f.ProjectID, f.Region, f.Module, string(f.Severity), f.ResourceName, f.Title, prepared[i].detail, nullIfEmpty(f.RawOutputPath), prepared[i].created); err != nil {
			return err
		}
	}
	return tx.Commit()
}
