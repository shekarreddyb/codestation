SELECT p.*
FROM ParentTable p
WHERE p.Status NOT IN ('Completed', 'Canceled')   -- parent not completed/canceled
  AND EXISTS (                                    -- must have at least one child
        SELECT 1
        FROM ChildTable c
        WHERE c.ParentId = p.ParentId
  )
  AND NOT EXISTS (                                -- no child that is NOT fully completed
        SELECT 1
        FROM ChildTable c
        WHERE c.ParentId = p.ParentId
          AND (
                c.Stage1Status <> 'Completed'
                OR c.Stage2Status <> 'Completed'
              )
  );