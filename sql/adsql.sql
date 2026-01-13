DECLARE @DecommissionedStatusId INT = 3; -- <-- put the correct ID here

-- Example list of account GUIDs
-- Replace with your real list
DECLARE @AccountIds TABLE (ServiceAccountId UNIQUEIDENTIFIER);
INSERT INTO @AccountIds (ServiceAccountId)
VALUES
 ('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'),
 ('11111111-2222-3333-4444-555555555555');
 -- add more as needed

;WITH EligibleAccounts AS
(
    SELECT asa.ServiceAccountId
    FROM ApplicationServiceAccount asa
    JOIN @AccountIds a ON a.ServiceAccountId = asa.ServiceAccountId
    WHERE NOT EXISTS
    (
        SELECT 1
        FROM ApplicationService s
        WHERE s.ServiceAccountId = asa.ServiceAccountId
          -- any service that is NOT in a "fully decommissioned" state
          AND s.ApprovalStatus NOT IN ('Decommissioned', 'Decommission Approved')
    )
)
UPDATE asa
SET asa.ApprovalStatusId = @DecommissionedStatusId
FROM ApplicationServiceAccount asa
JOIN EligibleAccounts ea
  ON ea.ServiceAccountId = asa.ServiceAccountId;