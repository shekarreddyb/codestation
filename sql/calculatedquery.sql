SELECT
    *,
    -----------------------------------
    -- Stage 1 Flags
    -----------------------------------
    Stage1Failed =
        CASE WHEN Stage1Status = 'Failed'
             THEN 1 ELSE 0 END,

    Stage1Late =
        CASE
            WHEN Stage1Status = 'Scheduled'
             AND Stage1ScheduledDate < CAST(GETDATE() AS DATE)
            THEN 1 ELSE 0
        END,

    Stage1Problem =
        CASE
            WHEN (Stage1Status = 'Failed')
              OR (Stage1Status = 'Scheduled'
                  AND Stage1ScheduledDate < CAST(GETDATE() AS DATE))
            THEN 1 ELSE 0
        END,

    Stage1YetToExecute =
        CASE
            WHEN Stage1Status = 'Scheduled'
             AND (Stage1ScheduledDate >= CAST(GETDATE() AS DATE)
                  OR Stage1ScheduledDate IS NULL)
            THEN 1 ELSE 0
        END,

    -----------------------------------
    -- Stage 2 Flags
    -----------------------------------
    Stage2Failed =
        CASE WHEN Stage2Status = 'Failed'
             THEN 1 ELSE 0 END,

    Stage2Late =
        CASE
            WHEN Stage2Status = 'Scheduled'
             AND Stage2ScheduledDate < CAST(GETDATE() AS DATE)
            THEN 1 ELSE 0
        END,

    Stage2Problem =
        CASE
            WHEN (Stage2Status = 'Failed')
              OR (Stage2Status = 'Scheduled'
                  AND Stage2ScheduledDate < CAST(GETDATE() AS DATE))
            THEN 1 ELSE 0
        END,

    Stage2YetToExecute =
        CASE
            WHEN Stage2Status = 'Scheduled'
             AND (Stage2ScheduledDate >= CAST(GETDATE() AS DATE)
                  OR Stage2ScheduledDate IS NULL)
            THEN 1 ELSE 0
        END,

    -----------------------------------
    -- Both Stage Success Flag (per row)
    -----------------------------------
    BothStagesSucceeded =
        CASE
            WHEN Stage1Status = 'Completed'
             AND Stage2Status = 'Completed'
            THEN 1 ELSE 0
        END,

    -----------------------------------
    -- Optional: Record-level Failure Type Labels
    -----------------------------------
    Stage1FailureType =
        CASE
            WHEN Stage1Status = 'Failed' THEN 'Failed'
            WHEN Stage1Status = 'Scheduled'
             AND Stage1ScheduledDate < CAST(GETDATE() AS DATE)
                THEN 'Scheduled Past Date'
            ELSE 'No Failure'
        END,

    Stage2FailureType =
        CASE
            WHEN Stage2Status = 'Failed' THEN 'Failed'
            WHEN Stage2Status = 'Scheduled'
             AND Stage2ScheduledDate < CAST(GETDATE() AS DATE)
                THEN 'Scheduled Past Date'
            ELSE 'No Failure'
        END,

    -----------------------------------
    -- Optional: High-level Request Status
    -- (order-level dashboard classification)
    -----------------------------------
    RequestLevelStatus =
        CASE
            WHEN Stage1Status = 'Completed'
             AND Stage2Status = 'Completed'
                THEN 'SucceededBothStages'

            WHEN (Stage1Status = 'Failed')
              OR (Stage1Status = 'Scheduled'
                  AND Stage1ScheduledDate < CAST(GETDATE() AS DATE))
                THEN 'FailedStage1'

            WHEN (Stage2Status = 'Failed')
              OR (Stage2Status = 'Scheduled'
                  AND Stage2ScheduledDate < CAST(GETDATE() AS DATE))
                THEN 'FailedStage2'

            WHEN Stage1Status = 'Scheduled'
             AND (Stage1ScheduledDate >= CAST(GETDATE() AS DATE)
                  OR Stage1ScheduledDate IS NULL)
                THEN 'PendingStage1'

            WHEN Stage2Status = 'Scheduled'
             AND (Stage2ScheduledDate >= CAST(GETDATE() AS DATE)
                  OR Stage2ScheduledDate IS NULL)
                THEN 'PendingStage2'

            ELSE 'InProgress'
        END

FROM YourTableName;
