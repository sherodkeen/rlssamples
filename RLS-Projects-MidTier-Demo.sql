-- Row-Level Security: Projects Demo
-- ---------------------------------
-- This demo shows how to implement RLS for a middle-tier application, where users
-- connect to the database through an application with a shared service account 
-- (your connection string), rather than using separate SQL users for each application
-- user. We use SESSION_CONTEXT to store the current UserId/TenantId so that the
-- RLS security policy knows which user to filter for. 

-- Scenario: Simple, multi-tenant project-tracking application. All tenants share the 
-- same underlying table.

-- Create an empty database
USE master
DROP DATABASE IF EXISTS RLS_Projects_Demo
CREATE DATABASE RLS_Projects_Demo
USE RLS_Projects_Demo -- note, if you're on Azure SQL Database, you must change the connection manually
go

-- Reset in case you're re-using an existing database
DROP SECURITY POLICY IF EXISTS Security.tenantSecurityPolicy
DROP FUNCTION IF EXISTS Security.tenantAccessPredicate
DROP FUNCTION IF EXISTS Security.tenantAccessPredicate_WriteAccess
DROP TABLE IF EXISTS Security.AppUsers
DROP TABLE IF EXISTS Projects
DROP SCHEMA IF EXISTS Security
DROP USER IF EXISTS AppUser
go

-- Create sample table with dummy data
CREATE TABLE Projects (
	ProjectId int identity(1,1) primary key,
	StartDate date,
	DueDate date,
	Name nvarchar(64),
	Status nvarchar(64),
	TenantId int DEFAULT CAST(SESSION_CONTEXT(N'TenantId') AS int) -- automatically set TenantId to the value in SESSION_CONTEXT
)

INSERT INTO Projects
	(StartDate, DueDate, Name, Status, TenantId)
VALUES 
	('2015-08-01', '2015-12-20', 'Project #137', 'On Track', 1), 
	('2015-08-08', '2015-10-20', 'Project #218', 'At Risk', 1), 
	('2015-08-15', '2016-03-15', 'Project #12', 'On Track', 2)
go

SELECT * FROM Projects
go

-- Create special user or service account for the application (without login for demo)
CREATE USER AppUser WITHOUT LOGIN 
go

GRANT SELECT, INSERT, UPDATE, DELETE ON Projects TO AppUser
DENY UPDATE ON Projects(TenantId) TO AppUser -- never allow data to change tenants
go

-- Enable Row-Level Security
CREATE SCHEMA Security
go

CREATE FUNCTION Security.tenantAccessPredicate(@TenantId int)
	RETURNS TABLE
	WITH SCHEMABINDING
AS
	-- Tenants can only access rows assigned to their TenantId
	RETURN SELECT 1 AS accessResult
	WHERE CAST(SESSION_CONTEXT(N'TenantId') AS int) = @TenantId
go

CREATE SECURITY POLICY Security.tenantSecurityPolicy
	ADD FILTER PREDICATE Security.tenantAccessPredicate(TenantId) ON dbo.Projects,
	ADD BLOCK PREDICATE Security.tenantAccessPredicate(TenantId) ON dbo.Projects AFTER INSERT -- other operations unnecessary
go

-- Tests!
EXECUTE AS USER = 'AppUser'

SELECT * FROM Projects -- 0 rows

EXEC sp_set_session_context N'TenantId', 2
SELECT * FROM Projects -- 1 row

EXEC sp_set_session_context N'TenantId', 1, @read_only = 1
SELECT * FROM Projects -- 2 rows

EXEC sp_set_session_context N'TenantId', 2 -- cannot change value, because TenantId is now read_only until this connection is closed (returned to pool)

INSERT INTO Projects (StartDate, DueDate, Name, Status) 
VALUES ('2015-09-24', '2015-12-31', 'Project #3', 'On Track') -- can insert value for current tenant (remember the default constraint!)

SELECT * FROM Projects

INSERT INTO Projects (StartDate, DueDate, Name, Status, TenantId) 
VALUES ('2015-10-31', '2016-04-25', 'Project #4', 'On Track', 1) -- can insert value for current tenant (this time explicit TenantId)

INSERT INTO Projects (StartDate, DueDate, Name, Status, TenantId) 
VALUES ('2016-01-01', '2016-12-31', 'Project #999', 'On Track', 2) -- blocked from inserting for wrong tenant

DELETE FROM Projects WHERE TenantId = 2 -- nothing to delete, because the filter predicate only allows access to current tenant's rows

SELECT * FROM Projects

REVERT
go

-- Let's make things more complicated...
-- 
-- Each tenant has its own users, who may or may not have write access to create/edit/delete projects:
--	 User 1: read-write for Tenant 1
--   User 2: read-only for Tenant 1
--	 User 3: read-write for Tenant 2
CREATE TABLE Security.AppUsers (
	UserId int,
	UserName nvarchar(256),
	WriteAccess bit,
	TenantId int
)

INSERT INTO Security.AppUsers 
	(UserId, UserName, WriteAccess, TenantId) 
VALUES
	(1, 'User 1', 1, 1),
	(2, 'User 2', 0, 1),
	(3, 'User 3', 1, 2)
go

SELECT * FROM Security.AppUsers
go

-- New predicate function for new blocking logic
CREATE FUNCTION Security.tenantAccessPredicate_WriteAccess(@TenantId int)
	RETURNS TABLE
	WITH SCHEMABINDING
AS
	-- Users can only insert, update, and delete if they have WriteAccess
	-- And only within their tenancy
	RETURN SELECT 1 AS operationResult
	FROM Security.AppUsers
	WHERE 
		TenantId = CAST(SESSION_CONTEXT(N'TenantId') AS int)
		AND UserId = CAST(SESSION_CONTEXT(N'UserId') AS int)
		AND WriteAccess = 1
		AND TenantId = @TenantId
go

-- Swap in the new predicate, this time for all operations
ALTER SECURITY POLICY Security.tenantSecurityPolicy
	DROP BLOCK PREDICATE ON dbo.Projects AFTER INSERT,
	ADD BLOCK PREDICATE Security.tenantAccessPredicate_WriteAccess(TenantId) ON dbo.Projects -- all operations
go

-- <Disconnect/reconnect to reset session_context>

-- App connects as User 1, Tenant 1, who does not have write access
EXECUTE AS USER = 'AppUser'
EXEC sp_set_session_context N'TenantId', 1, @read_only = 1
EXEC sp_set_session_context N'UserId', 2, @read_only = 1

SELECT * FROM Projects -- 4 rows

UPDATE Projects SET DueDate = '2020-12-31' WHERE ProjectId = 1 -- blocked

DELETE FROM Projects WHERE ProjectId = 1 -- blocked

INSERT INTO Projects (StartDate, DueDate, Name, Status) 
VALUES ('2016-01-01', '2016-12-31', 'Project #999', 'On Track') -- blocked

-- <Disconnect/reconnect to clear session_context>

-- App connects as User 2, who DOES have write access
EXECUTE AS USER = 'AppUser'
EXEC sp_set_session_context N'TenantId', 1, @read_only = 1
EXEC sp_set_session_context N'UserId', 1, @read_only = 1

SELECT * FROM Projects -- 4 rows

UPDATE Projects SET DueDate = '2016-12-31' WHERE ProjectId = 1 -- success

DELETE FROM Projects WHERE ProjectId = 1 -- success

INSERT INTO Projects (StartDate, DueDate, Name, Status) 
VALUES ('2016-01-01', '2016-06-15', 'Project #5', 'On Track') -- success

INSERT INTO Projects (StartDate, DueDate, Name, Status, TenantId) 
VALUES ('2017-01-01', '2020-12-31', 'Project #999', 'On Track', 2) -- still blocked from inserting for wrong tenant

REVERT
go

-- You can track the policies & predicates using these system views
SELECT * FROM sys.security_policies
SELECT * FROM sys.security_predicates
