--Create TempTable
CREATE TABLE #logininfo
(
  [AccountName]                [SYSNAME]                       NULL
 ,[Type]                       [SYSNAME]                       NULL
 ,[Privilege]                  [SYSNAME]                       NULL
 ,[MappedLogin]                [SYSNAME]                       NULL
 ,[PermissionPath]             [SYSNAME]                       NULL
);

CREATE TABLE #NonLogin
(
  [SID]                       [VARBINARY](85)                  NULL
 ,[Name]                      [SYSNAME]                        NULL
);

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

SELECT @v_Domain               = UPPER(LTRIM(RTRIM(REPLACE(@v_Domain, '.com', ''))));  

--INSERT #logininfo
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
  INTO #Login
  FROM sys.syslogins;

--Insert #NonLogin
INSERT #NonLogin
EXEC sp_validatelogins;

IF EXISTS (SELECT 1
             FROM [sysobjects]
			WHERE [name]       = 'server_principals')
BEGIN

  UPDATE a
     SET a.[TypeDesc]          = b.[Type_Desc]
	    ,a.[Active]            = CASE WHEN a.[TypeLogin] LIKE '%GROUP%'
		                              THEN 1
									  ELSE 0
									   END
	    ,a.[WhiteList]         = CASE WHEN a.[Name] LIKE '%$'
		                              THEN 1
									  ELSE 0
									   END
    FROM #Login                a
	JOIN sys.server_principals b
	  ON a.[Sid]               = b.[Sid];

END
ELSE
BEGIN

  UPDATE a
     SET a.[Active]            = CASE WHEN a.[TypeLogin] LIKE '%GROUP%'
		                              THEN 1
									  ELSE 0
									   END
	    ,a.[WhiteList]         = CASE WHEN a.[Name] LIKE '%$'
		                              THEN 1
									  ELSE 0
									   END
    FROM #Login                a;

END

/* UpDate the NonLogins */
UPDATE a
   SET a.[Active]              = 0
	  ,a.[TypeLogin]           = 'Deleted'
  FROM #Login                  a
  JOIN #NonLogin               b
    ON a.[SID]                 = b.[SID]

SELECT @v_Active               = COUNT(1)
  FROM #Login
 WHERE [Active]                = 1
   AND [IsLocalGroup]          = 1;

WHILE @v_Active                > 0
BEGIN -- Active > 0

  DECLARE c_Login CURSOR FAST_FORWARD FOR
    SELECT [Name]
	      ,[Rank] + 1
	  FROM #Login
	 WHERE [Active]                = 1
       AND [IsLocalGroup]          = 1;

  OPEN c_Login;

  FETCH c_Login INTO @v_Group, @v_Rank;

  WHILE @@FETCH_STATUS <> -1
  BEGIN -- c_login while -1

    IF (@@FETCH_STATUS <> -2)
	BEGIN -- c_login if -2

	  TRUNCATE TABLE #logininfo;
	  SELECT @v_SQL            = 'exec xp_logininfo ''' + @v_Group + ''', ''members''';

	  INSERT #logininfo
	  EXEC sp_executesql @v_SQL;


	  INSERT #Login
	  ([Name], [Rank], [CreateDate], [TypeLogin], [IsLocalGroup], [ParentGroup], [OrgParentGroup], [Active])
	  SELECT [AccountName]
	        ,@v_Rank
			,DATEADD(YEAR, -100, GETDATE())
	        ,CASE WHEN [AccountName] LIKE '%.%' 
			      THEN 'NT_LOGIN'
				  ELSE 'NT_GROUP'
				   END
	        ,CASE WHEN [AccountName] LIKE @v_SvrName + '%'
	              THEN 1
			      ELSE 0
			       END         AS [IsLocalGroup]
			,@v_Group
			,@v_Group
	        ,CASE WHEN [AccountName] LIKE '%.%'
	              THEN 0
			      ELSE 1
			       END
        FROM #logininfo;

      UPDATE #Login
	     SET [Active]          = 0
	   WHERE [Name]            = @v_Group

    END;  -- c_login if -2

  FETCH c_Login INTO @v_Group, @v_Rank;

  END; -- c_login while -1

  CLOSE c_Login;
  DEALLOCATE c_Login;

  SELECT @v_Active               = COUNT(1)
    FROM #Login
   WHERE [Active]                = 1
     AND [IsLocalGroup]          = 1;

END -- Active > 0

UPDATE #Login
   SET [Domain]                = CASE WHEN [Name] LIKE 'BUILTIN\%'
                                      THEN UPPER(@v_SvrName)
									  WHEN [Name] LIKE 'NT%'
									  THEN UPPER(@v_SvrName)
									  WHEN [Name] LIKE @v_SvrName + '\%'
									  THEN UPPER(@v_SvrName)
									  ELSE UPPER(@v_Domain)
									   END
      ,[Active]                = CASE WHEN [Name] LIKE 'NT%'
	                                  THEN 0
									  ELSE [Active]
									   END
 WHERE [TypeLogin]             LIKE 'NT%';

SELECT DISTINCT * FROM #Login ORDER BY 1;