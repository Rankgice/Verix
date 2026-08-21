---
name: go-gorm-model-standards
description: Use when adding, modifying, or reviewing Go GORM models under internal/model, including entity structs, parameter DTOs, CRUD methods, transaction-aware methods, filtering, pagination, and safe sorting. Treat internal/model/category.go as the canonical pattern, but do not generalize its custom GetByGroupId, GetByGroupIds, or GetByGroupIdsWithTx methods.
---

# Go GORM Model Standards

Use this skill for persistence-layer work in this repository's `internal/model` package. The canonical reference is `internal/model/category.go`. The rules below describe the shared model pattern in that file; they are not a request to copy category-specific business methods into every model.

## Scope and source of truth

- Follow the existing code in `internal/model/category.go` before introducing a new model-layer pattern.
- Use `internal/model/group.go`, `internal/model/item.go`, `internal/model/record.go`, and `internal/model/proxy.go` to check entity-specific variations.
- Follow the repository's existing `Id`/`GroupId` naming even where standard Go style would normally use `ID`/`GroupID`.
- Preserve the surrounding file's established API and domain behavior when extending an existing model.
- The following methods in `category.go` are explicitly user-customized and **must not be treated as generic requirements**:
  - `GetByGroupId`
  - `GetByGroupIds`
  - `GetByGroupIdsWithTx`
- Add relationship or convenience methods only when the target entity and its callers require them.

## Canonical model-file layout

Organize a model file in this general order, adjusting only when an existing file's API requires it:

1. `package model` and imports.
2. Persistent entity struct.
3. `TableName()`.
4. Order-field constants and the valid-field allowlist.
5. Query parameter struct.
6. Delete parameter struct.
7. Update parameter struct.
8. Model wrapper and constructor.
9. Create/save methods.
10. Parameterized update, delete, and list methods, with transaction variants.
11. Single-record lookup methods.
12. Batch or relationship helpers that are genuinely entity-specific.

Keep formatting `gofmt`-compatible. Standard-library imports come before a blank line and third-party imports.

## Entity structs and naming

### Names

- Define one exported domain struct per persisted entity.
- Use project-style initialisms: `Id`, `GroupId`, `CategoryId`, and similar names, not `ID`, `GroupID`, or `CategoryID`, unless an existing public API forces another spelling.
- Use singular entity names for structs and table wrappers: `Category`, `CategoryModel`.
- Use `m` for model receivers, `db` for the selected database handle, `res` for a GORM mutation result, singular names for one entity, and plural names for collections.

### Fields and tags

Use explicit GORM and JSON tags. Database and JSON names are snake_case:

```go
// Category 知识分类模型
type Category struct {
    Id          int64     `gorm:"column:id;primaryKey;autoIncrement;comment:数据库主键ID" json:"id"`
    GroupId     int64     `gorm:"column:group_id;not null;comment:分组ID" json:"group_id"`
    Name        string    `gorm:"column:name;not null;comment:分类名称" json:"name"`
    Description string    `gorm:"column:description;comment:分类描述" json:"description,omitempty"`
    CreatedAt   time.Time `gorm:"column:created_at;default:CURRENT_TIMESTAMP;comment:创建时间" json:"created_at"`
    UpdatedAt   time.Time `gorm:"column:updated_at;default:CURRENT_TIMESTAMP;comment:更新时间" json:"updated_at"`
}
```

- Specify the database column with `gorm:"column:..."`.
- Preserve primary-key and auto-increment declarations for the ID field.
- Include database comments in GORM tags when the surrounding models do so.
- Use `json:"..."` for externally serialized fields.
- Use `omitempty` for optional text or nullable values where the existing model does so.
- Use `time.Time` for timestamp fields and retain the repository's `CreatedAt`/`UpdatedAt` convention when applicable.
- Keep field-level Chinese comments aligned with the project's existing model style.

### Table name

Provide a value-receiver table-name method returning the exact singular lower-case table name:

```go
// TableName 指定表名
func (Category) TableName() string {
    return "category"
}
```

Do not rely on GORM's inferred table name when the repository defines an explicit table name.

## Sorting and order fields

Define named order fields and validate request input before constructing `ORDER BY`:

```go
const (
    CategoryOrderFieldId   = "id"
    CategoryOrderFieldName = "name"
)

var categoryOrderFieldMap = map[string]struct{}{
    CategoryOrderFieldId:   {},
    CategoryOrderFieldName: {},
}
```

Then use a safe GORM clause:

```go
sortBy := CategoryOrderFieldId
if _, ok := categoryOrderFieldMap[params.SortBy]; ok {
    sortBy = params.SortBy
}

db = db.Order(clause.OrderByColumn{
    Column: clause.Column{Name: sortBy},
    Desc:   params.IsDesc,
})
```

Rules:

- Default to a deterministic, valid field when `SortBy` is empty or invalid.
- Allow only fields in the explicit allowlist.
- Use `clause.OrderByColumn` and `clause.Column`, or an equally safe validated construction.
- Never interpolate unchecked request text into SQL ordering.
- Keep the exact sort direction and default expected by the target entity and its callers.

Some legacy sibling models build ordering with `fmt.Sprintf`; that is not the preferred pattern for new code. Use the allowlist approach from `category.go`.

## Parameter structs

### Query parameters

Define a flat `XxxQueryParams` value object for list filters, pagination, and sorting:

```go
type CategoryQueryParams struct {
    Id             int64     `json:"id"`
    IdList         []int64   `json:"id_list"`
    GroupId        int64     `json:"group_id"`
    Name           string    `json:"name"`
    Description    string    `json:"description"`
    CreatedAtStart time.Time `json:"created_at_start"`
    CreatedAtEnd   time.Time `json:"created_at_end"`
    UpdatedAtStart time.Time `json:"updated_at_start"`
    UpdatedAtEnd   time.Time `json:"updated_at_end"`
    Page           int       `json:"page"`
    PageSize       int       `json:"page_size"`
    SortBy         string    `json:"sort_by"`
    IsDesc         bool      `json:"is_desc"`
}
```

- Keep query parameters flat and explicit.
- Use zero values to mean that a filter was not supplied, matching the target model's behavior.
- Use `IdList` for multi-ID filtering only when the entity's API needs it.
- Document precedence rules next to the field or the relevant query block. In the canonical category model, a non-zero `Id` takes precedence over a non-empty `IdList`.
- Use inclusive time boundaries (`>=` for start and `<=` for end) when implementing the category-style range filters.

### Delete parameters

Use `XxxDeleteParams` for conditional deletes. Pointer fields distinguish an omitted condition from an explicit zero value or empty string:

```go
type CategoryDeleteParams struct {
    Id          *int64  `json:"id"`
    IdList      []int64 `json:"id_list"`
    GroupId     *int64  `json:"group_id"`
    Name        *string `json:"name"`
    Description *string `json:"description"`
}
```

- Apply a non-nil single ID before `IdList`.
- Add each non-nil optional predicate as a parameterized equality condition.
- Use `id IN ?` for a non-empty ID list.
- Do not add nil-parameter defensive behavior that is absent from the surrounding model contract; callers are expected to pass valid parameter objects.

### Update parameters

Use `XxxUpdateParams` for selective updates:

- Keep the ID as a value field used to identify the row.
- Use pointers for mutable fields so omitted fields are not confused with explicit zero, empty, or false values.
- Preserve the entity's GORM and JSON tags on the update DTO when that is the established pattern.

Example:

```go
type CategoryUpdateParams struct {
    Id          int64      `gorm:"column:id;primaryKey;autoIncrement;comment:数据库主键ID" json:"id"`
    GroupId     *int64     `gorm:"column:group_id;not null;comment:分组ID" json:"group_id"`
    Name        *string    `gorm:"column:name;not null;comment:分类名称" json:"name"`
    Description *string    `gorm:"column:description;comment:分类描述" json:"description,omitempty"`
    CreatedAt   *time.Time `gorm:"column:created_at;default:CURRENT_TIMESTAMP;comment:创建时间" json:"created_at"`
    UpdatedAt   *time.Time `gorm:"column:updated_at;default:CURRENT_TIMESTAMP;comment:更新时间" json:"updated_at"`
}
```

## Model wrapper and constructor

Encapsulate the default database handle in an exported model wrapper with an unexported field:

```go
// CategoryModel 知识分类模型
type CategoryModel struct {
    db *gorm.DB
}

// NewCategoryModel 创建知识分类模型
func NewCategoryModel(db *gorm.DB) *CategoryModel {
    return &CategoryModel{
        db: db,
    }
}
```

Use the corresponding `XxxModel` and `NewXxxModel` names for other entities. Do not create a new database connection inside model methods.

## Transaction handling

A transaction-aware method selects the supplied transaction, falling back to the model's default handle:

```go
db := m.db
if tx != nil {
    db = tx
}
```

Apply this selection before every operation in the method and use the selected `db` for all subsequent queries or mutations.

When both forms exist, the non-transaction wrapper delegates to the transaction-aware method with `nil`:

```go
// ListByParam 获取知识分类列表（统一查询方法）
func (m *CategoryModel) ListByParam(params *CategoryQueryParams) ([]*Category, int64, error) {
    return m.ListByParamWithTx(nil, params)
}
```

The same delegation pattern applies to `UpdateByParam`, `DeleteByParam`, and `BatchDelete` when their `WithTx` implementations are present. Do not claim a method is transaction-safe merely because another helper in the same model is; inspect the signature and implementation.

A model may expose `CreateWithTx` or `Save` without a symmetrical plain wrapper if that is the established API. Do not invent wrapper methods solely for symmetry.

## CRUD and error behavior

### Writes

- Use direct GORM operations (`Create`, `Save`, `Updates`, `Delete`) on the selected `db`.
- For selective updates, use the entity keyed by the update ID, as in `db.Model(&Category{Id: params.Id}).Updates(params)`.
- Return raw GORM errors; do not add model-layer error wrapping or custom translations unless the surrounding API explicitly requires it.
- Check errors immediately with `if err := ...; err != nil`.
- Return `RowsAffected` with the underlying error for update/delete methods that expose affected-row counts.

### Single-record lookups

For lookups such as `GetById`, treat a missing row as a normal empty result:

```go
func (m *CategoryModel) GetById(id int64) (*Category, error) {
    var category Category
    if err := m.db.First(&category, id).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, nil
        }
        return nil, err
    }
    return &category, nil
}
```

- Return `(nil, nil)` for `gorm.ErrRecordNotFound`.
- Return other database errors unchanged.
- Match the surrounding file's error comparison style when editing an existing file. In new code, `errors.Is(err, gorm.ErrRecordNotFound)` is also acceptable if it does not introduce inconsistency.

## List, filtering, and pagination

A category-style list method follows this sequence:

1. Select `m.db` or `tx`.
2. Start with `db.Model(&Category{})`.
3. Add conditional filters.
4. If both `Page > 0` and `PageSize > 0`, count the filtered query.
5. Apply `Offset((Page - 1) * PageSize)` and `Limit(PageSize)`.
6. Apply validated ordering and execute `Find`.
7. If pagination is disabled or invalid, set `total` to `int64(len(results))`.
8. Return the collection, total, and nil error.

Use parameterized conditions:

```go
if params.Id != 0 {
    db = db.Where("id = ?", params.Id)
} else if len(params.IdList) > 0 {
    db = db.Where("id IN ?", params.IdList)
}
if params.Name != "" {
    db = db.Where("name LIKE ?", "%"+params.Name+"%")
}
if !params.CreatedAtStart.IsZero() {
    db = db.Where("created_at >= ?", params.CreatedAtStart)
}
```

Rules:

- Use exact equality for identity and exact-match filters where the API requires it.
- Use `LIKE` with bound parameters for category-style partial text filters.
- Apply time predicates only when their `time.Time` value is non-zero.
- Count before offset and limit, and return `nil, 0, err` immediately if counting fails.
- When there is no valid pagination, return the number of fetched rows as `total`.
- Return `nil, 0, err` when the final query fails.
- Preserve entity-specific default ordering and direction instead of forcing every model to use the same timestamp order.

## Batch operations

When a model needs bulk deletion, use a wrapper plus a transaction-aware implementation:

```go
// BatchDelete 批量删除知识分类
func (m *CategoryModel) BatchDelete(ids []int64) (int64, error) {
    return m.BatchDeleteWithTx(nil, ids)
}

func (m *CategoryModel) BatchDeleteWithTx(tx *gorm.DB, ids []int64) (int64, error) {
    db := m.db
    if tx != nil {
        db = tx
    }
    res := db.Where("id IN ?", ids).Delete(&Category{})
    return res.RowsAffected, res.Error
}
```

Define empty-ID behavior deliberately for each operation. Do not rely on accidental ORM behavior that could result in an unsafe broad delete. Keep the return contract consistent with the target model.

## What is normative versus entity-specific

### Shared standards

The following are the reusable model conventions extracted from `category.go`:

- `Xxx` entity plus explicit `TableName()`.
- Project-style `Id` names and snake_case tags.
- Separate query, update, and delete parameter objects.
- Model wrapper with private `db *gorm.DB` and `NewXxxModel` constructor.
- Transaction selection using `m.db` unless `tx != nil`.
- Non-transaction wrappers delegating to `WithTx(nil)` when both APIs exist.
- Parameterized GORM filters and raw error propagation.
- `(nil, nil)` for not-found single-record lookups.
- Count-before-pagination and length fallback when pagination is disabled.
- Allowlisted, safely constructed sort fields.
- Rows-affected returns for the mutation methods that expose them.

### Do not overgeneralize

- `GetByGroupId`, `GetByGroupIds`, and `GetByGroupIdsWithTx` are category-specific relationship methods and are excluded from the standard.
- A model does not automatically need every possible `Create`, `Update`, `Delete`, `Save`, `GetAll`, existence, or relationship helper. Add only methods required by its API and callers.
- `IdList` precedence and empty-list handling are API/operation decisions; document them rather than assuming they apply identically everywhere.
- Existing models may have typed order constants, different default directions, or legacy query patterns. Preserve compatibility when modifying them, but use the safer category allowlist pattern for new ordering code.
- Transaction support is per-method. Verify signatures before using a helper inside a transaction.
- Do not introduce reflection or a generic repository abstraction just to remove straightforward per-model repetition.

## Compact implementation checklist

Before considering a new or changed model complete, verify:

- [ ] Entity and wrapper names follow the repository's `Id` naming convention.
- [ ] GORM and JSON tags use the correct database/serialized names.
- [ ] `TableName()` returns the intended table.
- [ ] Query/update/delete parameter structs have explicit semantics.
- [ ] Pointer fields are used where omission must differ from zero/empty values.
- [ ] ID-versus-ID-list precedence is documented and implemented.
- [ ] Every advertised `WithTx` method uses the selected transaction handle for all operations.
- [ ] Wrapper methods delegate to `WithTx(nil)` where applicable.
- [ ] Filters use bound parameters, not SQL string concatenation.
- [ ] Sort input is allowlisted and safely passed to GORM.
- [ ] Count occurs before offset/limit, and non-paginated totals use result length.
- [ ] Not-found lookups return `(nil, nil)`.
- [ ] Mutation methods return the expected affected-row count and raw error.
- [ ] Category-specific group lookup methods have not been copied as generic requirements.
- [ ] Comments match the surrounding Chinese, declarative style.
- [ ] `gofmt -w <changed model file>` passes; run `go vet ./...` and `go test ./...` when validating a model change.
