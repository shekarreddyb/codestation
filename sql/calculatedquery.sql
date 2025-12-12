SELECT
    d.*,

    ---------------------------------------------------------
    -- Stage 1 flags
    ---------------------------------------------------------
    Stage1FailedFlag =
        CASE WHEN d.Stage1Status = 'Failed'
             THEN 1 ELSE 0 END,

    Stage1LateScheduledFlag =
        CASE
            WHEN d.Stage1Status = 'Scheduled'
             AND d.Stage1ScheduledDate < CAST(GETDATE() AS DATE)
            THEN 1 ELSE 0
        END,

    Stage1ProblemFlag =
        CASE
            WHEN d.Stage1Status = 'Failed'
              OR (d.Stage1Status = 'Scheduled'
                  AND d.Stage1ScheduledDate < CAST(GETDATE() AS DATE))
            THEN 1 ELSE 0
        END,

    Stage1YetToExecuteFlag =
        CASE
            WHEN d.Stage1Status = 'Scheduled'
             AND (d.Stage1ScheduledDate >= CAST(GETDATE() AS DATE)
                  OR d.Stage1ScheduledDate IS NULL)
            THEN 1 ELSE 0
        END,

    ---------------------------------------------------------
    -- Stage 2 flags
    ---------------------------------------------------------
    Stage2FailedFlag =
        CASE WHEN d.Stage2Status = 'Failed'
             THEN 1 ELSE 0 END,

    Stage2LateScheduledFlag =
        CASE
            WHEN d.Stage2Status = 'Scheduled'
             AND d.Stage2ScheduledDate < CAST(GETDATE() AS DATE)
            THEN 1 ELSE 0
        END,

    Stage2ProblemFlag =
        CASE
            WHEN d.Stage2Status = 'Failed'
              OR (d.Stage2Status = 'Scheduled'
                  AND d.Stage2ScheduledDate < CAST(GETDATE() AS DATE))
            THEN 1 ELSE 0
        END,

    Stage2YetToExecuteFlag =
        CASE
            WHEN d.Stage2Status = 'Scheduled'
             AND (d.Stage2ScheduledDate >= CAST(GETDATE() AS DATE)
                  OR d.Stage2ScheduledDate IS NULL)
            THEN 1 ELSE 0
        END,

    ---------------------------------------------------------
    -- Both stages completed (row-level)
    ---------------------------------------------------------
    BothStagesSucceededFlag =
        CASE
            WHEN d.Stage1Status = 'Completed'
             AND d.Stage2Status = 'Completed'
            THEN 1 ELSE 0
        END,

    ---------------------------------------------------------
    -- Failure type labels (for pivots)
    ---------------------------------------------------------
    Stage1FailureType =
        CASE
            WHEN d.Stage1Status = 'Failed'
                THEN 'Failed'
            WHEN d.Stage1Status = 'Scheduled'
             AND d.Stage1ScheduledDate < CAST(GETDATE() AS DATE)
                THEN 'Scheduled Past Date'
            ELSE 'No Failure'
        END,

    Stage2FailureType =
        CASE
            WHEN d.Stage2Status = 'Failed'
                THEN 'Failed'
            WHEN d.Stage2Status = 'Scheduled'
             AND d.Stage2ScheduledDate < CAST(GETDATE() AS DATE)
                THEN 'Scheduled Past Date'
            ELSE 'No Failure'
        END

FROM dbo.YourTableName AS d;
