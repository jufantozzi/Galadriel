// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.16.0

package db

import (
	"context"
	"database/sql"
	"fmt"
)

type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func New(db DBTX) *Queries {
	return &Queries{db: db}
}

func Prepare(ctx context.Context, db DBTX) (*Queries, error) {
	q := Queries{db: db}
	var err error
	if q.createBundleStmt, err = db.PrepareContext(ctx, createBundle); err != nil {
		return nil, fmt.Errorf("error preparing query CreateBundle: %w", err)
	}
	if q.createFederationGroupStmt, err = db.PrepareContext(ctx, createFederationGroup); err != nil {
		return nil, fmt.Errorf("error preparing query CreateFederationGroup: %w", err)
	}
	if q.createHarvesterStmt, err = db.PrepareContext(ctx, createHarvester); err != nil {
		return nil, fmt.Errorf("error preparing query CreateHarvester: %w", err)
	}
	if q.createJoinTokenStmt, err = db.PrepareContext(ctx, createJoinToken); err != nil {
		return nil, fmt.Errorf("error preparing query CreateJoinToken: %w", err)
	}
	if q.createMemberStmt, err = db.PrepareContext(ctx, createMember); err != nil {
		return nil, fmt.Errorf("error preparing query CreateMember: %w", err)
	}
	if q.createMembershipStmt, err = db.PrepareContext(ctx, createMembership); err != nil {
		return nil, fmt.Errorf("error preparing query CreateMembership: %w", err)
	}
	if q.deleteBundleStmt, err = db.PrepareContext(ctx, deleteBundle); err != nil {
		return nil, fmt.Errorf("error preparing query DeleteBundle: %w", err)
	}
	if q.deleteFederationGroupStmt, err = db.PrepareContext(ctx, deleteFederationGroup); err != nil {
		return nil, fmt.Errorf("error preparing query DeleteFederationGroup: %w", err)
	}
	if q.deleteHarvesterStmt, err = db.PrepareContext(ctx, deleteHarvester); err != nil {
		return nil, fmt.Errorf("error preparing query DeleteHarvester: %w", err)
	}
	if q.deleteJoinTokenStmt, err = db.PrepareContext(ctx, deleteJoinToken); err != nil {
		return nil, fmt.Errorf("error preparing query DeleteJoinToken: %w", err)
	}
	if q.deleteMemberStmt, err = db.PrepareContext(ctx, deleteMember); err != nil {
		return nil, fmt.Errorf("error preparing query DeleteMember: %w", err)
	}
	if q.deleteMembershipStmt, err = db.PrepareContext(ctx, deleteMembership); err != nil {
		return nil, fmt.Errorf("error preparing query DeleteMembership: %w", err)
	}
	if q.findBundleByIDStmt, err = db.PrepareContext(ctx, findBundleByID); err != nil {
		return nil, fmt.Errorf("error preparing query FindBundleByID: %w", err)
	}
	if q.findBundleByMemberIDStmt, err = db.PrepareContext(ctx, findBundleByMemberID); err != nil {
		return nil, fmt.Errorf("error preparing query FindBundleByMemberID: %w", err)
	}
	if q.findFederationGroupByIDStmt, err = db.PrepareContext(ctx, findFederationGroupByID); err != nil {
		return nil, fmt.Errorf("error preparing query FindFederationGroupByID: %w", err)
	}
	if q.findHarvesterByIDStmt, err = db.PrepareContext(ctx, findHarvesterByID); err != nil {
		return nil, fmt.Errorf("error preparing query FindHarvesterByID: %w", err)
	}
	if q.findHarvestersByMemberIDStmt, err = db.PrepareContext(ctx, findHarvestersByMemberID); err != nil {
		return nil, fmt.Errorf("error preparing query FindHarvestersByMemberID: %w", err)
	}
	if q.findJoinTokenStmt, err = db.PrepareContext(ctx, findJoinToken); err != nil {
		return nil, fmt.Errorf("error preparing query FindJoinToken: %w", err)
	}
	if q.findJoinTokenByIDStmt, err = db.PrepareContext(ctx, findJoinTokenByID); err != nil {
		return nil, fmt.Errorf("error preparing query FindJoinTokenByID: %w", err)
	}
	if q.findJoinTokensByMemberIDStmt, err = db.PrepareContext(ctx, findJoinTokensByMemberID); err != nil {
		return nil, fmt.Errorf("error preparing query FindJoinTokensByMemberID: %w", err)
	}
	if q.findMemberByIDStmt, err = db.PrepareContext(ctx, findMemberByID); err != nil {
		return nil, fmt.Errorf("error preparing query FindMemberByID: %w", err)
	}
	if q.findMemberByTrustDomainStmt, err = db.PrepareContext(ctx, findMemberByTrustDomain); err != nil {
		return nil, fmt.Errorf("error preparing query FindMemberByTrustDomain: %w", err)
	}
	if q.findMembershipByIDStmt, err = db.PrepareContext(ctx, findMembershipByID); err != nil {
		return nil, fmt.Errorf("error preparing query FindMembershipByID: %w", err)
	}
	if q.findMembershipsByMemberIDStmt, err = db.PrepareContext(ctx, findMembershipsByMemberID); err != nil {
		return nil, fmt.Errorf("error preparing query FindMembershipsByMemberID: %w", err)
	}
	if q.listBundlesStmt, err = db.PrepareContext(ctx, listBundles); err != nil {
		return nil, fmt.Errorf("error preparing query ListBundles: %w", err)
	}
	if q.listFederationGroupsStmt, err = db.PrepareContext(ctx, listFederationGroups); err != nil {
		return nil, fmt.Errorf("error preparing query ListFederationGroups: %w", err)
	}
	if q.listHarvestersStmt, err = db.PrepareContext(ctx, listHarvesters); err != nil {
		return nil, fmt.Errorf("error preparing query ListHarvesters: %w", err)
	}
	if q.listJoinTokensStmt, err = db.PrepareContext(ctx, listJoinTokens); err != nil {
		return nil, fmt.Errorf("error preparing query ListJoinTokens: %w", err)
	}
	if q.listMembersStmt, err = db.PrepareContext(ctx, listMembers); err != nil {
		return nil, fmt.Errorf("error preparing query ListMembers: %w", err)
	}
	if q.listMembershipsStmt, err = db.PrepareContext(ctx, listMemberships); err != nil {
		return nil, fmt.Errorf("error preparing query ListMemberships: %w", err)
	}
	if q.updateBundleStmt, err = db.PrepareContext(ctx, updateBundle); err != nil {
		return nil, fmt.Errorf("error preparing query UpdateBundle: %w", err)
	}
	if q.updateFederationGroupStmt, err = db.PrepareContext(ctx, updateFederationGroup); err != nil {
		return nil, fmt.Errorf("error preparing query UpdateFederationGroup: %w", err)
	}
	if q.updateHarvesterStmt, err = db.PrepareContext(ctx, updateHarvester); err != nil {
		return nil, fmt.Errorf("error preparing query UpdateHarvester: %w", err)
	}
	if q.updateJoinTokenStmt, err = db.PrepareContext(ctx, updateJoinToken); err != nil {
		return nil, fmt.Errorf("error preparing query UpdateJoinToken: %w", err)
	}
	if q.updateMemberStmt, err = db.PrepareContext(ctx, updateMember); err != nil {
		return nil, fmt.Errorf("error preparing query UpdateMember: %w", err)
	}
	if q.updateMembershipStmt, err = db.PrepareContext(ctx, updateMembership); err != nil {
		return nil, fmt.Errorf("error preparing query UpdateMembership: %w", err)
	}
	return &q, nil
}

func (q *Queries) Close() error {
	var err error
	if q.createBundleStmt != nil {
		if cerr := q.createBundleStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing createBundleStmt: %w", cerr)
		}
	}
	if q.createFederationGroupStmt != nil {
		if cerr := q.createFederationGroupStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing createFederationGroupStmt: %w", cerr)
		}
	}
	if q.createHarvesterStmt != nil {
		if cerr := q.createHarvesterStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing createHarvesterStmt: %w", cerr)
		}
	}
	if q.createJoinTokenStmt != nil {
		if cerr := q.createJoinTokenStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing createJoinTokenStmt: %w", cerr)
		}
	}
	if q.createMemberStmt != nil {
		if cerr := q.createMemberStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing createMemberStmt: %w", cerr)
		}
	}
	if q.createMembershipStmt != nil {
		if cerr := q.createMembershipStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing createMembershipStmt: %w", cerr)
		}
	}
	if q.deleteBundleStmt != nil {
		if cerr := q.deleteBundleStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing deleteBundleStmt: %w", cerr)
		}
	}
	if q.deleteFederationGroupStmt != nil {
		if cerr := q.deleteFederationGroupStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing deleteFederationGroupStmt: %w", cerr)
		}
	}
	if q.deleteHarvesterStmt != nil {
		if cerr := q.deleteHarvesterStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing deleteHarvesterStmt: %w", cerr)
		}
	}
	if q.deleteJoinTokenStmt != nil {
		if cerr := q.deleteJoinTokenStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing deleteJoinTokenStmt: %w", cerr)
		}
	}
	if q.deleteMemberStmt != nil {
		if cerr := q.deleteMemberStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing deleteMemberStmt: %w", cerr)
		}
	}
	if q.deleteMembershipStmt != nil {
		if cerr := q.deleteMembershipStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing deleteMembershipStmt: %w", cerr)
		}
	}
	if q.findBundleByIDStmt != nil {
		if cerr := q.findBundleByIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing findBundleByIDStmt: %w", cerr)
		}
	}
	if q.findBundleByMemberIDStmt != nil {
		if cerr := q.findBundleByMemberIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing findBundleByMemberIDStmt: %w", cerr)
		}
	}
	if q.findFederationGroupByIDStmt != nil {
		if cerr := q.findFederationGroupByIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing findFederationGroupByIDStmt: %w", cerr)
		}
	}
	if q.findHarvesterByIDStmt != nil {
		if cerr := q.findHarvesterByIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing findHarvesterByIDStmt: %w", cerr)
		}
	}
	if q.findHarvestersByMemberIDStmt != nil {
		if cerr := q.findHarvestersByMemberIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing findHarvestersByMemberIDStmt: %w", cerr)
		}
	}
	if q.findJoinTokenStmt != nil {
		if cerr := q.findJoinTokenStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing findJoinTokenStmt: %w", cerr)
		}
	}
	if q.findJoinTokenByIDStmt != nil {
		if cerr := q.findJoinTokenByIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing findJoinTokenByIDStmt: %w", cerr)
		}
	}
	if q.findJoinTokensByMemberIDStmt != nil {
		if cerr := q.findJoinTokensByMemberIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing findJoinTokensByMemberIDStmt: %w", cerr)
		}
	}
	if q.findMemberByIDStmt != nil {
		if cerr := q.findMemberByIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing findMemberByIDStmt: %w", cerr)
		}
	}
	if q.findMemberByTrustDomainStmt != nil {
		if cerr := q.findMemberByTrustDomainStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing findMemberByTrustDomainStmt: %w", cerr)
		}
	}
	if q.findMembershipByIDStmt != nil {
		if cerr := q.findMembershipByIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing findMembershipByIDStmt: %w", cerr)
		}
	}
	if q.findMembershipsByMemberIDStmt != nil {
		if cerr := q.findMembershipsByMemberIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing findMembershipsByMemberIDStmt: %w", cerr)
		}
	}
	if q.listBundlesStmt != nil {
		if cerr := q.listBundlesStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing listBundlesStmt: %w", cerr)
		}
	}
	if q.listFederationGroupsStmt != nil {
		if cerr := q.listFederationGroupsStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing listFederationGroupsStmt: %w", cerr)
		}
	}
	if q.listHarvestersStmt != nil {
		if cerr := q.listHarvestersStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing listHarvestersStmt: %w", cerr)
		}
	}
	if q.listJoinTokensStmt != nil {
		if cerr := q.listJoinTokensStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing listJoinTokensStmt: %w", cerr)
		}
	}
	if q.listMembersStmt != nil {
		if cerr := q.listMembersStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing listMembersStmt: %w", cerr)
		}
	}
	if q.listMembershipsStmt != nil {
		if cerr := q.listMembershipsStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing listMembershipsStmt: %w", cerr)
		}
	}
	if q.updateBundleStmt != nil {
		if cerr := q.updateBundleStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing updateBundleStmt: %w", cerr)
		}
	}
	if q.updateFederationGroupStmt != nil {
		if cerr := q.updateFederationGroupStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing updateFederationGroupStmt: %w", cerr)
		}
	}
	if q.updateHarvesterStmt != nil {
		if cerr := q.updateHarvesterStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing updateHarvesterStmt: %w", cerr)
		}
	}
	if q.updateJoinTokenStmt != nil {
		if cerr := q.updateJoinTokenStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing updateJoinTokenStmt: %w", cerr)
		}
	}
	if q.updateMemberStmt != nil {
		if cerr := q.updateMemberStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing updateMemberStmt: %w", cerr)
		}
	}
	if q.updateMembershipStmt != nil {
		if cerr := q.updateMembershipStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing updateMembershipStmt: %w", cerr)
		}
	}
	return err
}

func (q *Queries) exec(ctx context.Context, stmt *sql.Stmt, query string, args ...interface{}) (sql.Result, error) {
	switch {
	case stmt != nil && q.tx != nil:
		return q.tx.StmtContext(ctx, stmt).ExecContext(ctx, args...)
	case stmt != nil:
		return stmt.ExecContext(ctx, args...)
	default:
		return q.db.ExecContext(ctx, query, args...)
	}
}

func (q *Queries) query(ctx context.Context, stmt *sql.Stmt, query string, args ...interface{}) (*sql.Rows, error) {
	switch {
	case stmt != nil && q.tx != nil:
		return q.tx.StmtContext(ctx, stmt).QueryContext(ctx, args...)
	case stmt != nil:
		return stmt.QueryContext(ctx, args...)
	default:
		return q.db.QueryContext(ctx, query, args...)
	}
}

func (q *Queries) queryRow(ctx context.Context, stmt *sql.Stmt, query string, args ...interface{}) *sql.Row {
	switch {
	case stmt != nil && q.tx != nil:
		return q.tx.StmtContext(ctx, stmt).QueryRowContext(ctx, args...)
	case stmt != nil:
		return stmt.QueryRowContext(ctx, args...)
	default:
		return q.db.QueryRowContext(ctx, query, args...)
	}
}

type Queries struct {
	db                            DBTX
	tx                            *sql.Tx
	createBundleStmt              *sql.Stmt
	createFederationGroupStmt     *sql.Stmt
	createHarvesterStmt           *sql.Stmt
	createJoinTokenStmt           *sql.Stmt
	createMemberStmt              *sql.Stmt
	createMembershipStmt          *sql.Stmt
	deleteBundleStmt              *sql.Stmt
	deleteFederationGroupStmt     *sql.Stmt
	deleteHarvesterStmt           *sql.Stmt
	deleteJoinTokenStmt           *sql.Stmt
	deleteMemberStmt              *sql.Stmt
	deleteMembershipStmt          *sql.Stmt
	findBundleByIDStmt            *sql.Stmt
	findBundleByMemberIDStmt      *sql.Stmt
	findFederationGroupByIDStmt   *sql.Stmt
	findHarvesterByIDStmt         *sql.Stmt
	findHarvestersByMemberIDStmt  *sql.Stmt
	findJoinTokenStmt             *sql.Stmt
	findJoinTokenByIDStmt         *sql.Stmt
	findJoinTokensByMemberIDStmt  *sql.Stmt
	findMemberByIDStmt            *sql.Stmt
	findMemberByTrustDomainStmt   *sql.Stmt
	findMembershipByIDStmt        *sql.Stmt
	findMembershipsByMemberIDStmt *sql.Stmt
	listBundlesStmt               *sql.Stmt
	listFederationGroupsStmt      *sql.Stmt
	listHarvestersStmt            *sql.Stmt
	listJoinTokensStmt            *sql.Stmt
	listMembersStmt               *sql.Stmt
	listMembershipsStmt           *sql.Stmt
	updateBundleStmt              *sql.Stmt
	updateFederationGroupStmt     *sql.Stmt
	updateHarvesterStmt           *sql.Stmt
	updateJoinTokenStmt           *sql.Stmt
	updateMemberStmt              *sql.Stmt
	updateMembershipStmt          *sql.Stmt
}

func (q *Queries) WithTx(tx *sql.Tx) *Queries {
	return &Queries{
		db:                            tx,
		tx:                            tx,
		createBundleStmt:              q.createBundleStmt,
		createFederationGroupStmt:     q.createFederationGroupStmt,
		createHarvesterStmt:           q.createHarvesterStmt,
		createJoinTokenStmt:           q.createJoinTokenStmt,
		createMemberStmt:              q.createMemberStmt,
		createMembershipStmt:          q.createMembershipStmt,
		deleteBundleStmt:              q.deleteBundleStmt,
		deleteFederationGroupStmt:     q.deleteFederationGroupStmt,
		deleteHarvesterStmt:           q.deleteHarvesterStmt,
		deleteJoinTokenStmt:           q.deleteJoinTokenStmt,
		deleteMemberStmt:              q.deleteMemberStmt,
		deleteMembershipStmt:          q.deleteMembershipStmt,
		findBundleByIDStmt:            q.findBundleByIDStmt,
		findBundleByMemberIDStmt:      q.findBundleByMemberIDStmt,
		findFederationGroupByIDStmt:   q.findFederationGroupByIDStmt,
		findHarvesterByIDStmt:         q.findHarvesterByIDStmt,
		findHarvestersByMemberIDStmt:  q.findHarvestersByMemberIDStmt,
		findJoinTokenStmt:             q.findJoinTokenStmt,
		findJoinTokenByIDStmt:         q.findJoinTokenByIDStmt,
		findJoinTokensByMemberIDStmt:  q.findJoinTokensByMemberIDStmt,
		findMemberByIDStmt:            q.findMemberByIDStmt,
		findMemberByTrustDomainStmt:   q.findMemberByTrustDomainStmt,
		findMembershipByIDStmt:        q.findMembershipByIDStmt,
		findMembershipsByMemberIDStmt: q.findMembershipsByMemberIDStmt,
		listBundlesStmt:               q.listBundlesStmt,
		listFederationGroupsStmt:      q.listFederationGroupsStmt,
		listHarvestersStmt:            q.listHarvestersStmt,
		listJoinTokensStmt:            q.listJoinTokensStmt,
		listMembersStmt:               q.listMembersStmt,
		listMembershipsStmt:           q.listMembershipsStmt,
		updateBundleStmt:              q.updateBundleStmt,
		updateFederationGroupStmt:     q.updateFederationGroupStmt,
		updateHarvesterStmt:           q.updateHarvesterStmt,
		updateJoinTokenStmt:           q.updateJoinTokenStmt,
		updateMemberStmt:              q.updateMemberStmt,
		updateMembershipStmt:          q.updateMembershipStmt,
	}
}
