

[CmdletBinding()]
Param(
    [parameter(Position=0,mandatory=$false,ValueFromPipeline)]
    [ValidateNotNullOrEmpty()]
    [string]$SQLInstance='C0SQLMON'
)

Function Connect-InternalSQLServer
{   
    [CmdletBinding()]
    Param(
         [String]$SQLInstance,
         [String]$Database,
         [String]$SQLExec          
         )

    Process
    {
        # Open connection and Execute sql against server using Windows Auth
        $Connection = [System.Data.SqlClient.SqlConnection]::new()
        $SqlCmd     = [System.Data.SqlClient.SqlCommand]::new()
        $SqlAdapter = [System.Data.SqlClient.SqlDataAdapter]::new()
        $DataSet    = [System.Data.DataSet]::new()

        $SQLConnectionString         = "Data Source=$SQLInstance;Initial Catalog=$Database;Integrated Security=SSPI;Application Name=Powershell Data Module" 
        $Connection.ConnectionString = $SQLConnectionString        
        $SqlCmd.CommandText          = $SQLExec
        $SqlCmd.CommandTimeout       = 0
        $SqlCmd.Connection           = $Connection        
        $SqlAdapter.SelectCommand    = $SqlCmd
   
        # Insert results into Dataset table
        $SqlAdapter.Fill($DataSet) | out-null

        # Eval Return Set
        if ($DataSet.Tables.Count -ne 0) 
        {
            $sqlresults = $DataSet.Tables[0]
        }
        else
        {
            $sqlresults =$null
        }

        # Close connection to sql server
        $Connection.Close()

        Write-Output $sqlresults
    }
}

# Define Scope Variables
$LocalHostName = $env:computername
$scriptDirectory = $PSScriptRoot                                                     # This will store the directory of the script itself
$outputCSVPath = $scriptDirectory + "\" + $SQLInstance + "_SvrLogins.csv"            # Concatenate the script directory with "\" + $SQLInstance + "_SvrLogins.csv"

# Connect to the SQL Server and get the Logins
$SQLCMD1 = "

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

"

try
{
  # Prep SQL Connection objects to Source Server
  $results1 = Connect-InternalSQLServer -SQLInstance $SQLInstance -Database 'master' -SQLExec $SQLCMD1 -ErrorAction Stop
}
catch
{
    $SQLError = $PSItem.tostring()

    # Log it
    $Now = (Get-Date -f "MM/dd/yyyy HH:mm:ss.fff")
    $LogMsgSeqNo++  
    $LogMsg = ('[{0}] - Server Logins - Error getting logins from [{1}] , Error: [{2}]' -f $now, $LocalHostName , $SQLError)

    Write-Host($LogMsg)

    throw($LogMsg)
}

#To see the results in a TableGrid popup
#$results1 | ogv

$filteredResults = $results1 | Where-Object { $_.TypeLogin -eq 'NT_Group' -and $_.Active -eq 1 }
$results1 = [System.Collections.ArrayList]@($results1)

#Grab the Domain or Domain alias and remove it
$filteredResults2 = $results1 | Where-Object { 
    ($_.TypeDesc -eq 'WINDOWS_GROUP' -or $_.TypeDesc -eq 'WINDOWS_LOGIN') -and
    ($_.IsLocalGroup -eq 0) -and
    ($_.Domain -ne $SQLInstance) } 


# Select the first matching entry and extract the 'Name' property
$firstName = $filteredResults2 | Select-Object -First 1 -ExpandProperty Name

# Split the string by '\' and select the first part
$domain = $firstname.Split('\')[0]

#$results1 | ogv
#$results1.GetType()

foreach($group in $filteredResults)
{

    #$GroupName      = $group.Name -replace 'PF\\', ''
    if ($group.Name -like 'Builtin*') {
        $GroupName = $group.Name -replace 'Builtin\\', ''
    } 
    else {
        $GroupName      = $group.Name -replace "$Domain\\", ''
    }
    if ($group.Name -like 'Builtin*') {
        $ParentGroup = $group.Name 
    }
    else {
        $ParentGroup = $group.Name -replace "$Domain\\", ''
    }

    $Rank           = $group.Rank 
    $TypeLogin      = $group.TypeLogin
    $OrgParentGroup = $group.OrgParentGroup
    $Active         = '0'


    $Rank           = [int]$Rank + 1

    # Write-Host($GroupName, $ParentGroup)

    $GroupMembers = Get-ADGroupMember $GroupName -Recursive | `
        Select-Object `
            SamAccountName, `
            objectClass, `
            distinguishedName, `
            @{Name='ComputerName'; Expression={$Instance}}, `
            @{Name='GroupName'; Expression={$ParentGroup}}, `
            @{Name='Rank'; Expression={$Rank}}, `
            @{Name='Active'; Expression={$Active}}

    foreach($Member in $GroupMembers)
    {

        $MemberName   = $Member.SamAccountName
        $MemberType   = IF ($Member.objectClass -like 'user') {'NT_LOGIN'} else {'NT_GROUP'}
        $MemberParent = $Member.GroupName
        $MemberRank   = $Member.Rank
        $MemberDomain = $Member.distinguishedName -replace '^.+?,DC=(.+)$','$1' -replace ',DC=','.'
        $Active       = IF ($Member.objectClass -like 'user') {'0'} else {'1'}
        #$Active = if ($Member.objectClass -like 'user' -or $Member.SamAccountName -like '$') {'0'} else {'1'}
        $OrgParentGroup2 = $Member.GroupName

        #Need a way to fix this hard codeded issue!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        if ($Member.SamAccountName -eq 'C0SKYPE01$') {$Active       = '0'}

        if ($OrgParentGroup -eq [System.DBNull]::Value){$OrgParentGroup = $OrgParentGroup2}

        $NewObject    = [PSCustomObject]@{
            Name           = $MemberName
            Domain         = $MemberDomain
            Sid            = $null
            TypeDesc       = $MemberType
            Rank           = $MemberRank
            CreateDate     = $null
            TypeLogin      = $MemberType
            sysadmin       = $null
            securityadmin  = $null
            serveradmin    = $null
            processadmin   = $null
            diskadmin      = $null
            dbcreator      = $null
            bulkadmin      = $null
            IsLocalGroup   = $null
            WhiteList      = $null
            ParentGroup    = $MemberParent
            OrgParentGroup = $OrgParentGroup
            Active         = $Active
        }
        
        if ($MemberName.Length -gt 1) 
        {
            $results1.Add($NewObject) | Out-Null

            if ($Active -eq 1){
                $filteredResults.add($NewObject)
            }
        }
        $NewObject = $null

    }
    $GroupMembers = $null

}

#To see the results in a TableGrid popup
#$results1 | ogv

#Create a datatable object to hold the finalresults
$FinalResult = New-Object System.Data.DataTable
    
# Define the schema for $result1
$FinalResult.Columns.Add("Name", [System.String]) | Out-Null
$FinalResult.Columns.Add("Domain", [System.String]) | Out-Null
$FinalResult.Columns.Add("Sid", [System.String]) | Out-Null
$FinalResult.Columns.Add("TypeDesc", [System.String]) | Out-Null
$FinalResult.Columns.Add("Rank", [System.String]) | Out-Null
$FinalResult.Columns.Add("CreateDate", [System.DateTime]) | Out-Null
$FinalResult.Columns.Add("TypeLogin", [System.String]) | Out-Null
$FinalResult.Columns.Add("sysadmin", [System.String]) | Out-Null
$FinalResult.Columns.Add("securityadmin", [System.String]) | Out-Null
$FinalResult.Columns.Add("serveradmin", [System.String]) | Out-Null
$FinalResult.Columns.Add("processadmin", [System.String]) | Out-Null
$FinalResult.Columns.Add("diskadmin", [System.String]) | Out-Null
$FinalResult.Columns.Add("dbcreator", [System.String]) | Out-Null
$FinalResult.Columns.Add("bulkadmin", [System.String]) | Out-Null
$FinalResult.Columns.Add("IsLocalGroup", [System.String]) | Out-Null
$FinalResult.Columns.Add("WhiteList", [System.String]) | Out-Null
$FinalResult.Columns.Add("ParentGroup", [System.String]) | Out-Null
$FinalResult.Columns.Add("OrgParentGroup", [System.String]) | Out-Null
$FinalResult.Columns.Add("Active", [System.String]) | Out-Null


# Filter rows for Rank = 0 (similar to OrgParent in SQL)
$orgParentRows = $results1 | Where-Object { $_.Rank -eq 0 }


foreach($Mem in $orgParentRows)
{

  try 
  {

# Create a new DataRow using the DataTable's NewRow method
    $dataRow = $FinalResult.NewRow()

    $dataRow["Name"]             = $Mem.Name -replace "$Domain\\", ''
    $dataRow["Domain"]           = if ($Mem.Domain -ne [DBNull]::Value) {$Mem.Domain.ToUpper() -replace "\.COM$", ''}
    $dataRow["TypeDesc"]         = $Mem.TypeDesc
    $dataRow["Rank"]             = $Mem.Rank
    $dataRow["CreateDate"]       = if ($Mem.CreateDate -eq $null) {[DBNull]::Value}  else {$Mem.CreateDate}
    $dataRow["TypeLogin"]        = $Mem.TypeLogin
    $dataRow["sysadmin"]         = if ($Mem.sysadmin -eq $null)      {'0'}           else {$Mem.sysadmin} 
    $dataRow["securityadmin"]    = if ($Mem.securityadmin -eq $null) {'0'}           else {$Mem.securityadmin}
    $dataRow["serveradmin"]      = if ($Mem.serveradmin -eq $null)   {'0'}           else {$Mem.serveradmin}
    $dataRow["processadmin"]     = if ($Mem.processadmin -eq $null)  {'0'}           else {$Mem.processadmin}
    $dataRow["diskadmin"]        = if ($Mem.diskadmin -eq $null)     {'0'}           else {$Mem.diskadmin}
    $dataRow["dbcreator"]        = if ($Mem.dbcreator -eq $null)     {'0'}           else {$Mem.dbcreator}
    $dataRow["bulkadmin"]        = if ($Mem.bulkadmin -eq $null)     {'0'}           else {$Mem.sysadmin}
    $dataRow["IsLocalGroup"]     = $Mem.IsLocalGroup
    $dataRow["WhiteList"]        = $Mem.WhiteList
    $dataRow["ParentGroup"]      = $Mem.ParentGroup
    $dataRow["OrgParentGroup"]   = $Mem.OrgParentGroup
    $dataRow["Active"]           = $Mem.Active

# Add the DataRow to the DataTable
    $FinalResult.Rows.Add($dataRow)

  }
  catch
  {

    Write-Error "An error occurred while creating or adding the DataRow: $_"

  }

}
##################################End of Rank 0########################################################

# Filter rows for Rank > 0
$rankGreaterThanZeroRows = $results1 | Where-Object { $_.Rank -gt 0 }


foreach($Row in $rankGreaterThanZeroRows)
{

  try 
  {

# Create a new DataRow using the DataTable's NewRow method
    $dataRow = $FinalResult.NewRow()

#Get the orgParent info
    $matchingParentRow = $orgParentRows | Where-Object { $_.Name -replace "$Domain\\", '' -eq $row.OrgParentGroup }

    $dataRow["Name"]             = $Row.Name -replace "$Domain\\", ''
    $dataRow["Domain"]           = if ($Row.Domain -ne [DBNull]::Value) {$Row.Domain.ToUpper() -replace "\.COM$", ''}   #$Row.Domain 
    $dataRow["TypeDesc"]         = $Row.TypeDesc
    $dataRow["Rank"]             = $Row.Rank
    $dataRow["CreateDate"]       = if ($Row.CreateDate -eq $null) {[DBNull]::Value}  else {$Row.CreateDate}
    $dataRow["TypeLogin"]        = $Row.TypeLogin
    $dataRow["sysadmin"]         = if ($matchingParentRow.sysadmin -eq $null)      {'0'}  else {$matchingParentRow.sysadmin} 
    $dataRow["securityadmin"]    = if ($matchingParentRow.securityadmin -eq $null) {'0'}  else {$matchingParentRow.securityadmin}
    $dataRow["serveradmin"]      = if ($matchingParentRow.serveradmin -eq $null)   {'0'}  else {$matchingParentRow.serveradmin}
    $dataRow["processadmin"]     = if ($matchingParentRow.processadmin -eq $null)  {'0'}  else {$matchingParentRow.processadmin}
    $dataRow["diskadmin"]        = if ($matchingParentRow.diskadmin -eq $null)     {'0'}  else {$matchingParentRow.diskadmin}
    $dataRow["dbcreator"]        = if ($matchingParentRow.dbcreator -eq $null)     {'0'}  else {$matchingParentRow.dbcreator}
    $dataRow["bulkadmin"]        = if ($matchingParentRow.bulkadmin -eq $null)     {'0'}  else {$matchingParentRow.sysadmin}
    $dataRow["IsLocalGroup"]     = $Row.IsLocalGroup
    $dataRow["WhiteList"]        = $Row.WhiteList
    $dataRow["ParentGroup"]      = $Row.ParentGroup
    $dataRow["OrgParentGroup"]   = $Row.OrgParentGroup
    $dataRow["Active"]           = $Row.Active

# Add the DataRow to the DataTable
    $FinalResult.Rows.Add($dataRow)

  }
  catch
  {

    Write-Error "An error occurred while creating or adding the DataRow: $_"

  }

}


#$FinalResult | Sort-Object -Property Name | ogv

# Export the collection to a CSV file, overwriting if the file exists
$FinalResult | Sort-Object -Property Name | Export-Csv -Path $outputCSVPath -NoTypeInformation -Force










