WITH package_manager_processes AS (
  SELECT
    aid,
    ComputerName,
    UserName,
    TargetProcessId,
    ParentProcessId,
    ImageFileName,
    CommandLine,
    ContextTimeStamp
  FROM falcon_events
  WHERE event_simpleName = 'ProcessRollup2'
    AND ContextTimeStamp >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
    AND REGEXP_LIKE(
      LOWER(ImageFileName),
      '\\\\(node|npm|npx|pip|pip3|python|python[0-9.]+|mvn)\\.exe$'
    )
),
suspicious_children AS (
  SELECT
    aid,
    ComputerName,
    UserName,
    TargetProcessId,
    ParentProcessId,
    ImageFileName    AS child_image,
    CommandLine      AS child_cmdline,
    ContextTimeStamp AS child_time
  FROM falcon_events
  WHERE event_simpleName = 'ProcessRollup2'
    AND ContextTimeStamp >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
    AND (
      REGEXP_LIKE(LOWER(ImageFileName),
        '\\\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\\.exe$')
      OR REGEXP_LIKE(CommandLine,
        '(?i)(curl |wget |invoke-webrequest|invoke-restmethod|downloadstring|downloadfile)')
      OR REGEXP_LIKE(CommandLine,
        '(?i)(\\.aws\\\\credentials|\\.ssh\\\\|\\.npmrc|github_token|aws_secret|npm_token)')
      OR REGEXP_LIKE(CommandLine, '(?i)-e(nc|ncoded)?\\s+[A-Za-z0-9+/=]{20,}')
    )
)
SELECT
  p.ComputerName,
  p.UserName,
  p.ImageFileName  AS parent_pkg_manager,
  p.CommandLine    AS install_command,
  c.child_image,
  c.child_cmdline,
  c.child_time,
  CASE
    WHEN c.child_cmdline ILIKE '%-enc %'           THEN 'ENCODED_EXEC'
    WHEN c.child_cmdline ILIKE '%credentials%'
      OR c.child_cmdline ILIKE '%.ssh%'
      OR c.child_cmdline ILIKE '%token%'           THEN 'CRED_HARVEST'
    WHEN c.child_cmdline ILIKE '%curl%'
      OR c.child_cmdline ILIKE '%wget%'
      OR c.child_cmdline ILIKE '%downloadstring%'  THEN 'PAYLOAD_DOWNLOAD'
    ELSE 'SUSPICIOUS_SHELL'
  END AS detection_type
FROM package_manager_processes p
JOIN suspicious_children c
  ON p.aid = c.aid
 AND p.TargetProcessId = c.ParentProcessId
 AND c.child_time BETWEEN p.ContextTimeStamp
                      AND p.ContextTimeStamp + INTERVAL '5 minutes'
ORDER BY c.child_time DESC;