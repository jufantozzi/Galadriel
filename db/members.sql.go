// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.16.0
// source: members.sql

package db

import (
	"context"

	"github.com/jackc/pgtype"
)

const createMember = `-- name: CreateMember :one
INSERT INTO members(trust_domain, status)
VALUES ($1, $2)
RETURNING id, trust_domain, status, created_at, updated_at
`

type CreateMemberParams struct {
	TrustDomain string
	Status      Status
}

func (q *Queries) CreateMember(ctx context.Context, arg CreateMemberParams) (Member, error) {
	row := q.queryRow(ctx, q.createMemberStmt, createMember, arg.TrustDomain, arg.Status)
	var i Member
	err := row.Scan(
		&i.ID,
		&i.TrustDomain,
		&i.Status,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const deleteMember = `-- name: DeleteMember :exec
DELETE
FROM members
WHERE id = $1
`

func (q *Queries) DeleteMember(ctx context.Context, id pgtype.UUID) error {
	_, err := q.exec(ctx, q.deleteMemberStmt, deleteMember, id)
	return err
}

const findMemberByID = `-- name: FindMemberByID :one
SELECT id, trust_domain, status, created_at, updated_at
FROM members
WHERE id = $1
`

func (q *Queries) FindMemberByID(ctx context.Context, id pgtype.UUID) (Member, error) {
	row := q.queryRow(ctx, q.findMemberByIDStmt, findMemberByID, id)
	var i Member
	err := row.Scan(
		&i.ID,
		&i.TrustDomain,
		&i.Status,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const findMemberByTrustDomain = `-- name: FindMemberByTrustDomain :one
SELECT id, trust_domain, status, created_at, updated_at
FROM members
WHERE trust_domain = $1
`

func (q *Queries) FindMemberByTrustDomain(ctx context.Context, trustDomain string) (Member, error) {
	row := q.queryRow(ctx, q.findMemberByTrustDomainStmt, findMemberByTrustDomain, trustDomain)
	var i Member
	err := row.Scan(
		&i.ID,
		&i.TrustDomain,
		&i.Status,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const listMembers = `-- name: ListMembers :many
SELECT id, trust_domain, status, created_at, updated_at
FROM members
ORDER BY trust_domain
`

func (q *Queries) ListMembers(ctx context.Context) ([]Member, error) {
	rows, err := q.query(ctx, q.listMembersStmt, listMembers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Member
	for rows.Next() {
		var i Member
		if err := rows.Scan(
			&i.ID,
			&i.TrustDomain,
			&i.Status,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateMember = `-- name: UpdateMember :one
UPDATE members
SET trust_domain = $2,
    status     = $3,
    updated_at = now()
WHERE id = $1
RETURNING id, trust_domain, status, created_at, updated_at
`

type UpdateMemberParams struct {
	ID          pgtype.UUID
	TrustDomain string
	Status      Status
}

func (q *Queries) UpdateMember(ctx context.Context, arg UpdateMemberParams) (Member, error) {
	row := q.queryRow(ctx, q.updateMemberStmt, updateMember, arg.ID, arg.TrustDomain, arg.Status)
	var i Member
	err := row.Scan(
		&i.ID,
		&i.TrustDomain,
		&i.Status,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}