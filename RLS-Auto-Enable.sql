-- Apply Row-Level Security to all tables
-- --------------------------------------
-- This stored procedure automatically generates a security policy that adds a filter predicate
-- on all tables with a specified column name and type. For details and usage examples, see 
-- http://blogs.msdn.com/b/sqlsecurity/archive/2015/03/31/apply-row-level-security-to-all-tables-helper-script.aspx

CREATE PROCEDURE dbo.sp_enable_rls_auto (
	/* The type for the tenant ID column. It could be short, int or bigint. */
	@rlsColType sysname,	

	/* The name for the tenant ID column. All tables that match the column name & type will be affected. */
	@rlsColName sysname,

	/* The schema name where the policy will be applied.
	   If null (default), the policy will be applied to tables in all schemas in the database. */
	@applyToSchema sysname = null,

	/* Set to 1 to disable all existing policies that affect the identified target tables.
	   If set to 0 (default), this function will fail if there is an existing policy on any of these tables. */
	@deactivateExistingPolicies bit = 0,

	/* Schema name for new RLS objects. If it does not exist, it will be created. */
	@rlsSchemaName sysname = N'rls',

	/* The name of an existing function in the RLS schema that will be used as the predicate.
	   If null (default), a new function will be created with a simple CONTEXT_INFO = tenant ID filter. */
	@rlsPredicateFunctionName sysname = null,

	/* Set to 1 to allow CONTEXT_INFO = null to have access to all rows. Default is 0.
	   Not applicable if @rlsPredicateFunctionName is set with a custom predicate function. 
	   Note that on Azure SQL Database, CONTEXT_INFO is pre-populated with a unique connection GUID (not null), 
	   so you must execute SET CONTEXT_INFO 0x to reset it to null for this 'admin' mode to work. */
	@isNullAdmin bit = 0,

	/* If @isNullAdmin = 1, set to 1 to optimize the CONTEXT_INFO = null disjunction into a range query. 
	   Not applicable if @rlsPredicateFunctionName is set with a custom predicate function. */
	@isNullAdminOptimized bit = 1,

	/* If set, the predicate function will allow only this user to access rows.
	   Use only for middle-tier scenarios, where this is the shared application user name. 
	   Not applicable if @rlsPredicateFunctionName is set with a custom predicate function. */
	@restrictedToAppUserName sysname = null,

	/* Set to 1 to print the commands (on by default). */
	@printCommands bit = 1,

	/* Set to 1 to execute the commands (off by default). */
	@runCommands bit = 0
)
AS
DECLARE @typeId int
DECLARE @typeLen int
DECLARE @typeMin bigint
DECLARE @typeMax bigint
DECLARE @cmd nvarchar(max)
DECLARE @fnmin sysname
DECLARE @fnmax sysname
DECLARE @rlsPredicateName sysname

IF( @runCommands = 0 AND @printCommands = 0 )
BEGIN
	raiserror( 'Invalid arguments. @runCommands = 0 can only be used if @printCommands = 1', 16, 1 )
	return
END

SELECT @typeId = system_type_id, @typeLen = max_length FROM sys.types 
	WHERE name = @rlsColType AND system_type_id in (48, 52, 56, 127)

IF( @typeId  is null OR @typeLen is null)
BEGIN
	raiserror( 'Error on type. Only integer types are supported', 16, 1 )
	return
END

IF( schema_id(@rlsSchemaName) is null )
BEGIN
	SET @cmd = N'CREATE SCHEMA ' + quotename(@rlsSchemaName)
	IF( @printCommands = 1 )
	BEGIN
		PRINT @cmd + N'
go';
	END
	IF( @runCommands = 1 )
		EXEC (@cmd)
END

-- #REGION Predicate function defintion
IF( @rlsPredicateFunctionName is null )
BEGIN

	-- #REGION Predicate function creation
	
	--------------------------------------------------------
	-- The following 2 UDFs are only used for a particular disjunction case (null=admin)
	--
	IF( @isNullAdminOptimized = 1 AND @isNullAdmin = 1 )
	BEGIN
		SELECT @typeMax = (convert(bigint, POWER(2.0, (8*@typeLen)-1))-1)
		SELECT @typeMin = (convert(bigint, POWER(2.0, (8*@typeLen)-1))*-1)

		SET @fnmin = @rlsColType + N'_lo_' + convert(nvarchar(100), getdate(), 127)
		SET @cmd = N'CREATE FUNCTION ' + quotename(@rlsSchemaName) + N'.' + quotename(@fnmin) + N'() RETURNS ' + quotename(@rlsColType) + N'
WITH SCHEMABINDING 
AS BEGIN 
 RETURN CASE WHEN context_info() is null THEN
	' + convert(nvarchar(256), @typeMin) + N' ELSE 
	convert(' + quotename(@rlsColType) + N', convert(varbinary(' + convert(nvarchar(256), @typeLen) + N'), context_info())) END 
END'
		IF( @printCommands = 1 )
		BEGIN
			PRINT @cmd + N'
go';
		END
		IF( @runCommands = 1 )
			EXEC (@cmd)

		SET @fnmax = @rlsColType + N'_hi_' + convert(nvarchar(100), getdate(), 127)
		SET @cmd = N'CREATE FUNCTION ' + quotename(@rlsSchemaName) + N'.' + quotename(@fnmax) + N'() RETURNS ' + quotename(@rlsColType) + N'
WITH SCHEMABINDING 
AS BEGIN 
 RETURN CASE WHEN context_info() is null THEN
	' + convert(nvarchar(256), @typeMax) + N' ELSE 
	convert(' + quotename(@rlsColType) + N', convert(varbinary(' + convert(nvarchar(256), @typeLen) + N'), context_info())) END 
END'
		IF( @printCommands = 1 )
		BEGIN
			PRINT @cmd + N'
go';
		END
		IF( @runCommands = 1 )
			EXEC (@cmd)
	END
	-- ENDOF IF( @isNullAdminOptimized = 1 AND @isNullAdmin = 1 )

	SET @rlsPredicateName  = 'fn_predicate_' + @rlsColName + '_' + convert(nvarchar(100), getdate(), 127)
	SET @cmd = N'CREATE FUNCTION ' + quotename(@rlsSchemaName) + N'.' + quotename(@rlsPredicateName) 
		+ N'(@TenantId ' + quotename(@rlsColType) + N' )
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS fn_accessResult 
	WHERE ';
	IF( @restrictedToAppUserName is not null )
	BEGIN
		SET @cmd = @cmd + N'  
		DATABASE_PRINCIPAL_ID() = DATABASE_PRINCIPAL_ID (''' + replace(@restrictedToAppUserName, '''', '''''') + N''') AND (';
	END

	SET @cmd = @cmd + N'
		'

	IF( @isNullAdmin = 1 )
	BEGIN
		IF( @isNullAdminOptimized = 1 )
		BEGIN
			SET @cmd = @cmd + N'@TenantId BETWEEN ' + quotename(@rlsSchemaName) + N'.' + quotename(@fnmin) + N'() AND ' + quotename(@rlsSchemaName) + N'.' + quotename(@fnmax) + N'()'
		END
		ELSE
		BEGIN
			SET @cmd = @cmd + N'CONTEXT_INFO() is null OR'
			SET @cmd = @cmd + N'
			'
		END
	END

	IF( @isNullAdmin = 0 OR @isNullAdminOptimized = 0 )
	BEGIN
		SET @cmd = @cmd + N'CONVERT(' + quotename(@rlsColType) + N', CONVERT(varbinary(' + convert(nvarchar(10), @typeLen )+ '), CONTEXT_INFO())) = @TenantId'
	END

	SET @cmd = @cmd + N'
	'

	IF( @restrictedToAppUserName is not null )
	BEGIN
	SET @cmd = @cmd + N')'
	END

	SET @cmd = @cmd + N'
	';

	IF( @printCommands = 1 )
	BEGIN
		PRINT @cmd + N'
go';
	END
	IF( @runCommands = 1 )
		EXEC (@cmd)

	-- #ENDREGION Predicate function creation
END
ELSE
BEGIN
	IF( (SELECT count(*) FROM sys.objects 
		WHERE name = @rlsPredicateFunctionName 
			AND schema_id = schema_id( @rlsSchemaName )
			AND type = 'IF') = 0 )
	BEGIN
		raiserror( 'Error on User Defined function. Could not find a matching predicate function.', 16, 1 )
		return
	END
	SET @rlsPredicateName = @rlsPredicateFunctionName
END
-- #ENDREGION Predicate function defintion


DECLARE @schemaName sysname;
DECLARE @tableName sysname;
DECLARE @columnName sysname;
DECLARE @tableId sysname;

DECLARE cur_columns CURSOR FOR 
	SELECT objs.object_id, schema_name(objs.schema_id), objs.name, cols.name FROM sys.columns cols, sys.objects objs 
		WHERE cols.name = @rlsColName AND @typeId = system_type_id 
			AND cols.object_id = objs.object_id
			AND ( @applyToSchema is NULL OR objs.schema_id = schema_id(@applyToSchema) )
		ORDER BY objs.schema_id, objs.object_id;

OPEN cur_columns 

FETCH NEXT FROM cur_columns INTO @tableId, @schemaName, @tableName, @columnName

DECLARE @rlsPolicyName sysname
SET @rlsPolicyName = N'secpol_' + @rlsColName + '_' + convert(nvarchar(100), getdate(), 127)
SET @cmd = N'CREATE SECURITY POLICY ' + quotename(@rlsSchemaName) + N'.' + quotename(@rlsPolicyName);

DECLARE @AddPredicateTemplate nvarchar(max);
SET @AddPredicateTemplate = N'ADD FILTER PREDICATE ' + quotename(@rlsSchemaName) + N'.'+ quotename(@rlsPredicateName)

DECLARE @errMessage nvarchar(max)
DECLARE @firstTableHit int
DECLARE @errorHit bit
SET @firstTableHit = 0
SET @errorHit = 0

WHILE @errorHit = 0 AND @@FETCH_STATUS = 0
BEGIN

	DECLARE @existingPolicy sysname
	SET @existingPolicy  = null
	DECLARE @existingPolicySchema sysname
	select @existingPolicy = pols.name, @existingPolicySchema = schema_name(pols.schema_id) 
		FROM sys.security_policies pols, sys.security_predicates preds 
		WHERE 
			preds.target_object_id = @tableId
			AND pols.is_enabled = 1
			AND preds.object_id = pols.object_id

	IF( @existingPolicy is not null )
	BEGIN
		DECLARE @innerCmd nvarchar(max)
		if( @deactivateExistingPolicies = 1 )
		BEGIN
			SET @innerCmd = 'ALTER SECURITY POLICY ' + quotename(@existingPolicySchema) + N'.' + quotename(@existingPolicy) + N' WITH ( STATE = OFF )'
			BEGIN TRY
				IF( @printCommands = 1 )
				BEGIN
					PRINT @innerCmd + N'
go';
				END
				IF( @runCommands = 1 )
					EXEC (@innerCmd)
			END TRY
			BEGIN CATCH
				IF( @printCommands = 1 )
					PRINT '---------- LAST COMMAND FAILED -----------'
				SET @errMessage = 'Error while altering the existing policy. Error number: ' + convert(nvarchar(100), error_number()) + N' Error Message: ' + error_message()
				raiserror( @innerCmd, 16, 1 )		
				SET @errorHit = 1
				SET @errorHit = 1
			END CATCH
		END
		ELSE
		BEGIN
			SET @innerCmd = 'Error. No table ' + quotename(@schemaName) + '.' + quotename(@tableName) 
				+ N' has an active policy defined: ' + quotename(@existingPolicySchema) + '.' + quotename(@existingPolicy)
			raiserror( @innerCmd, 16, 1 )
			SET @errorHit = 1
		END
	END

	IF( @firstTableHit = 0 )
	BEGIN
		SET @firstTableHit = 1
	END
	ELSE
	BEGIN
		SET @cmd = @cmd + N','
	END

	SET @cmd = @cmd + N'
	' + @AddPredicateTemplate + N'(' + quotename(@ColumnName) + ') ON ' 
	+ quotename(@schemaName) + '.' + quotename(@tableName)

	FETCH NEXT FROM cur_columns INTO @tableId, @schemaName, @tableName, @columnName
END

CLOSE cur_columns;
DEALLOCATE cur_columns;

SET @cmd = @cmd + N'
';
 
IF( @errorHit = 0 AND @firstTableHit > 0 )
BEGIN
	BEGIN TRY
		IF( @printCommands = 1 )
		BEGIN
			PRINT @cmd + N'
go'
		END
		IF( @runCommands = 1 )
			EXEC (@cmd)
	END TRY
	BEGIN CATCH
		IF( @printCommands = 1 )
			PRINT '---------- LAST COMMAND FAILED -----------'
		SET @errMessage = 'Error while creating the policy. Error number: ' + convert(nvarchar(100), error_number()) + N' Error Message: ' + error_message()
		raiserror( @errMessage, 16, 1 )		
		SET @errorHit = 1
	END CATCH
END
ELSE
BEGIN
	raiserror( 'Error. No tables match the criteria', 16, 1 )
	return
END

IF( @errorHit != 0 )
BEGIN	
	-- Roll back
	DECLARE @cleanupCmd nvarchar(max)

	IF( @rlsPredicateFunctionName is not null )
	BEGIN
		SET @cleanupCmd = N'BEGIN TRY
		DROP FUNCTION ' + quotename(@rlsSchemaName) + N'.' + quotename(@rlsPredicateName) + N';
		';
		IF( @isNullAdminOptimized = 1 AND @isNullAdmin = 1 )
		BEGIN
			SET @cleanupCmd = @cleanupCmd + N'	DROP FUNCTION ' + quotename(@rlsSchemaName) + N'.' + quotename(@fnmin) + N'
		DROP FUNCTION ' + quotename(@rlsSchemaName) + N'.' + quotename(@fnmax) + N'
	'
		END
		SET @cleanupCmd = @cleanupCmd + N'END TRY
	BEGIN CATCH
	END CATCH;'
			IF( @printCommands = 1 )
			BEGIN
				PRINT '---------- CLEANUP -----------'
				PRINT @cleanupCmd + N'
go'
			END
			IF( @runCommands = 1 )
				EXEC (@cleanupCmd)
	END
	RETURN
END
go

-- example
EXEC sp_enable_rls_auto
 @rlsColType = 'int', 
 @rlsColName = 'TenantId',
 @applyToSchema = null,
 @deactivateExistingPolicies = 1,
 @rlsSchemaName = N'rls',
 @rlsPredicateFunctionName = null,
 @isNullAdmin = 0,
 @isNullAdminOptimized = 0,
 @restrictedToAppUserName = 'AppUser',
 @printCommands = 1,
 @runCommands = 0 -- set to 1 to execute output
go
