WITH ParentChildStatus AS (
    SELECT
        p.ParentId,
        p.Status AS ParentStatus,
        SUM(CASE WHEN c.Status <> 'Completed' THEN 1 ELSE 0 END) AS NotCompletedChildCount,
        COUNT(*) AS ChildCount
    FROM ParentTable p
    JOIN ChildTable c ON c.ParentId = p.ParentId
    GROUP BY p.ParentId, p.Status
)
SELECT p.*
FROM ParentTable p
JOIN ParentChildStatus pcs ON pcs.ParentId = p.ParentId
WHERE p.Status = 'Stage2'
  AND pcs.ChildCount > 0
  AND pcs.NotCompletedChildCount = 0;    -- all children completed