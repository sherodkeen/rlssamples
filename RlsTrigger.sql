-- First create a sproc that our trigger will call to add a table to an existing security policy
-- This SP will perform the ALTER SECURITY POLICY DDL
--
CREATE PROCEDURE dbo.sp_add_table_to_policy(
	@rlsSchema sysname, @rlsPolicy sysname, 
	@rlsPredicateSchema sysname, @rlsPredicateName sysname,
	@targetScehma sysname, @targetTable sysname, @targetColName sysname,
	@forcePolicy bit = 0 )
AS
BEGIN
	IF( @forcePolicy = 0 )
	BEGIN
		IF( NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = object_id(quotename(@targetScehma) + N'.' + quotename(@targetTable)) AND name = @targetColName))
		BEGIN
			print 'Skipping Policy creation since the table does not include the target column'
			return;
		END
	END

	DECLARE @cmd nvarchar(max);
	SET @cmd = N'ALTER SECURITY POLICY ' + quotename(@rlsSchema) + N'.' + quotename(@rlsPolicy) + N'
	ADD FILTER PREDICATE ' + quotename(@rlsPredicateSchema) + N'.'+ quotename(@rlsPredicateName) + N'(' + quotename(@targetColName) + N')
	ON ' + quotename(@targetScehma) + N'.' + quotename(@targetTable) + N';'
	EXECUTE( @cmd )
END
go

-- Usage Example

CREATE SCHEMA [rls]
go

CREATE FUNCTION [rls].[fn_predicate_TenantId](@TenantId [int] )
 RETURNS TABLE
 WITH SCHEMABINDING
AS
 RETURN SELECT 1 AS fn_accessResult 
 WHERE  CONVERT([int], CONVERT(varbinary(4), CONTEXT_INFO())) = @TenantId
go

-- Create a dummy table in order to create a Security Policy
--
CREATE TABLE [rls].[dummy](tenantId int)
go

CREATE SECURITY POLICY [rls].[secpol_TenantId]
	ADD FILTER PREDICATE [rls].[fn_predicate_TenantId]([TenantId]) ON [rls].[dummy]
go

-- Create a special user with elevated permissions that the trigger can use to execute the sproc to apply the policy (least privilege)
--
CREATE USER [user_rls_trigger] WITHOUT LOGIN
go

GRANT EXECUTE ON [dbo].[sp_add_table_to_policy] TO [user_rls_trigger]
go

-- Create a trigger on CREATE TABLE DDL to apply the policy upon table creation.
--
CREATE TRIGGER trig_apply_policy ON DATABASE 
WITH EXECUTE AS 'user_rls_trigger'
AFTER CREATE_TABLE
AS
	DECLARE @schema sysname
	DECLARE @tableName sysname
	DECLARE @data xml
	-- Set the following bit to 1 to force new tables to include the target column and be included in teh policy
	DECLARE @forcePolicy bit = 1
	-- target column name for the filtering predicate
	DECLARE @targetColumnName sysname = 'tenantId';
	SET @data = EVENTDATA()
	SET @schema = @data.value('(/EVENT_INSTANCE/SchemaName)[1]', 'nvarchar(256)')
	SET @tableName = @data.value('(/EVENT_INSTANCE/ObjectName)[1]', 'nvarchar(256)')
	BEGIN TRY
		EXEC [dbo].[sp_add_table_to_policy] 'rls', 'secpol_TenantId', 'rls', 'fn_predicate_TenantId', @schema, @tableName, @targetColumnName, @forcePolicy;
	END TRY
	BEGIN CATCH
		declare @err int = error_number()
		declare @msg nvarchar(256) = error_message()
		raiserror( N'Table cannot be added to policy, it requires to have a column named %s in order to apply the filter. Inner error Number: %s',
			12, 1, @targetColumnName, @msg )
	END CATCH
go

-- Create certificate for special user, and use it to sign the sproc and make sure we will have the right permissions when executing it
--
CREATE CERTIFICATE cert_rls ENCRYPTION BY PASSWORD = '<<ThrowAway password124@>>' WITH SUBJECT  = 'RLS policy tigger' 
go
CREATE USER cert_rls FOR CERTIFICATE cert_rls 
go
GRANT REFERENCES TO [cert_rls]
GRANT ALTER ANY SECURITY POLICY TO [cert_rls]
GRANT SELECT ON [rls].[fn_predicate_TenantId] TO [cert_rls]
GRANT ALTER ON [rls].[fn_predicate_TenantId] TO [cert_rls]
GRANT ALTER ON SCHEMA::[rls] TO [cert_rls]
go
ADD SIGNATURE TO [dbo].[sp_add_table_to_policy]  BY CERTIFICATE [cert_rls] WITH PASSWORD = '<<ThrowAway password124@>>'
go
ALTER CERTIFICATE [cert_rls] REMOVE PRIVATE KEY
go

----- DEMO ----

CREATE USER toto WITHOUT LOGIN
go

GRANT CREATE TABLE TO toto
go

CREATE SCHEMA toto AUTHORIZATION toto
go


EXECUTE AS USER ='toto'
go

CREATE TABLE toto.t( TenantId int )
go

REVERT
go

SELECT object_name(object_id) as [policy_name], object_name(target_object_id) as [target_object_name], * FROM sys.security_predicates 
go

ALTER SECURITY POLICY [rls].[secpol_TenantId]
	DROP FILTER PREDICATE ON toto.t
go

DROP TABLE toto.t
go
