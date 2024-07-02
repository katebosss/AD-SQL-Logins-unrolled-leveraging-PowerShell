
DECLARE @v_SvrName             [SYSNAME] = CONVERT(SYSNAME, SERVERPROPERTY('MACHINENAME'))
       ,@v_Group               [SYSNAME]
	   ,@v_Rank                [INT]     = 0
	   ,@v_Active              [INT]     = 0
	   ,@v_SQL                 [NVARCHAR](2000)
	   ,@v_Domain              [SYSNAME];

-- Get the Domain Name
EXEC master.dbo.xp_regread
    'HKEY_LOCAL_MACHINE',
    'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
    'NV Domain',
    @v_Domain OUTPUT;
	
SELECT [Name]
      ,CONVERT(SYSNAME, NULL)  AS [Domain]
      ,[Sid]
      ,CONVERT(SYSNAME, NULL)  AS [TypeDesc]
	  ,@v_Rank                 AS [Rank]
	  ,[CreateDate]
	  ,CASE WHEN [isntname]    = 0
	        THEN 'SQL_LOGIN'
			WHEN [isntgroup]   = 1
			THEN 'NT_GROUP'
			WHEN [isntuser]    = 1
			THEN 'NT_USER'
			 END               AS [TypeLogin]
      ,[sysadmin]
	  ,[securityadmin]
	  ,[serveradmin]
	  ,[setupadmin]
	  ,[processadmin]
	  ,[diskadmin]
	  ,[dbcreator]
	  ,[bulkadmin]
	  ,CASE WHEN [Name]      LIKE @v_SvrName + '%'
	        THEN 1
			ELSE 0
			 END               AS [IsLocalGroup]
	  ,CONVERT(INT, NULL)      AS [WhiteList]
	  ,CONVERT(SYSNAME, NULL)  AS [ParentGroup]
	  ,CONVERT(SYSNAME, NULL)  AS [OrgParentGroup]
	  ,1                       AS [Active]
  --INTO #Login
  FROM sys.syslogins
 ORDER BY 1;