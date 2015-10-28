-- Row-Level Security: Hospital Demo
-- ---------------------------------
-- This demo uses SQL Server's built-in security system (users and roles) to limit access
-- to rows of patient data for nurses and doctors in a hospital.

-- SETUP
-- Create an empty database, tables, insert some dummy data, and create users and roles 
-- for several nurses and doctors.
DROP DATABASE IF EXISTS RLS_Hospital_Demo
CREATE DATABASE RLS_Hospital_Demo
USE RLS_Hospital_Demo -- note, if you're on Azure SQL Database, you must change the connection manually
go

CREATE TABLE [patients] ( 
	patientId INT PRIMARY KEY,
	name nvarchar(256), 
	room int, 
	wing int, 
	startTime datetime, 
	endTime datetime 
)
CREATE TABLE [employees] ( 
	empId int PRIMARY KEY, 
	name nvarchar(256), 
	databasePrincipalId int 
)
CREATE TABLE [staffDuties] ( 
	empId int, 
	wing int, 
	startTime datetime, 
	endTime datetime 
)
CREATE TABLE [wings] ( 
	wingId int PRIMARY KEY, 
	name nvarchar(128) 
)
go

CREATE ROLE [nurse]
CREATE ROLE [doctor]
go

GRANT SELECT, UPDATE ON [patients] to [nurse]
GRANT SELECT, UPDATE ON [patients] to [doctor]
go

-- Create a user for each nurse & doctor (without logins to simplify demo)
-- Add to corresponding role (in practice, these could also be Windows Groups)
-- Add to employees table
CREATE USER [nurse_BartonC] WITHOUT LOGIN
ALTER ROLE [nurse] ADD MEMBER [nurse_BartonC]
INSERT INTO [employees] VALUES ( 1001, N'Clara Barton', DATABASE_PRINCIPAL_ID('nurse_BartonC'));
go

CREATE USER [nurse_AllenM] WITHOUT LOGIN
ALTER ROLE [nurse] ADD MEMBER [nurse_AllenM]
INSERT INTO [employees] VALUES ( 1002, N'Moyra Allen', DATABASE_PRINCIPAL_ID('nurse_AllenM') );
go

CREATE USER [nurse_NightingaleF] WITHOUT LOGIN
ALTER ROLE [nurse] ADD MEMBER [nurse_NightingaleF]
INSERT INTO [employees] VALUES ( 1003, N'Florence Nightingale', DATABASE_PRINCIPAL_ID('nurse_NightingaleF'));
go

CREATE USER [doctor_ApgarV] WITHOUT LOGIN
ALTER ROLE [doctor] ADD MEMBER [doctor_ApgarV]
INSERT INTO [employees] VALUES ( 2001, N'Virginia Apgar', DATABASE_PRINCIPAL_ID('doctor_ApgarV'));
go

CREATE USER [doctor_CharcotJ] WITHOUT LOGIN
ALTER ROLE [doctor] ADD MEMBER [doctor_CharcotJ]
INSERT INTO [employees] VALUES ( 2002, N'Jean-Martin Charcot', DATABASE_PRINCIPAL_ID('doctor_CharcotJ'));
go


INSERT INTO wings VALUES( 1, N'North');
INSERT INTO wings VALUES( 2, N'South');
INSERT INTO wings VALUES( 3, N'Emergency');
go

INSERT INTO [patients] VALUES ( 01, N'Ludwig van Beethoven', 101, 1, '12-17-2015',  '03-26-2016')
INSERT INTO [patients] VALUES ( 02, N'Niccolo Paganini', 102, 1, '10-27-2015',  '05-27-2016')
INSERT INTO [patients] VALUES ( 05, N'Pyotr Ilyich Tchaikovsky', 107, 1, '5-7-2015',  '11-6-2015')
INSERT INTO [patients] VALUES ( 03, N'Carl Philipp Emanuel Bach', 203, 2, '3-8-2015',  '12-14-2015')
INSERT INTO [patients] VALUES ( 04, N'Wolfgang Amadeus Mozart', 205, 2, '1-27-2015',  '12-5-2015')
INSERT INTO [patients] VALUES ( 06, N'Philip Morris Glass', 301, 3, '1-31-2015',  null)
INSERT INTO [patients] VALUES ( 07, N'Edvard Hagerup Grieg', 308, 3, '6-15-2015',  '9-4-2015')

INSERT INTO [staffDuties] VALUES ( 1001, 1, '01-01-2015', '12-31-2015' )
INSERT INTO [staffDuties] VALUES ( 1001, 2, '01-01-2016', '12-31-2016' )
INSERT INTO [staffDuties] VALUES ( 1002, 1, '01-01-2015', '06-30-2015' )
INSERT INTO [staffDuties] VALUES ( 1002, 2, '07-01-2015', '12-31-2015' )
INSERT INTO [staffDuties] VALUES ( 1002, 3, '01-01-2016', '12-31-2016' )
INSERT INTO [staffDuties] VALUES ( 1003, 3, '01-01-2015', '12-31-2016' )

INSERT INTO [staffDuties] VALUES ( 2001, 1, '01-01-2015', '12-31-2015' )
INSERT INTO [staffDuties] VALUES ( 2001, 3, '01-01-2016', '12-31-2016' )
INSERT INTO [staffDuties] VALUES ( 2002, 1, '01-01-2015', '12-31-2016' )
go

-- END SETUP




-- Quick look at existing schema
SELECT * FROM patients;
go

-- Flatten employees and staffDuties to easily view assignments
SELECT s.empId, name, user_name(databasePrincipalId) as SqlUserName, wing, startTime, endTime 
	FROM staffDuties s 
	INNER JOIN employees e ON (e.empId = s.empId) 
ORDER BY empId;
go

-- ENABLE ROW-LEVEL SECURITY

-- Create separate schema for RLS objects (best practice)
CREATE SCHEMA rls
go

-- RLS predicate allows access to rows based on a user's role and assigned staff duties.
-- Because users have both SELECT and UPDATE permissions, we will use this function as a
-- filter predicate (filter which rows are accessible by SELECT and UPDATE queries) and a 
-- block predicate after update (prevent user from updating rows to be outside of visible range).
CREATE FUNCTION rls.accessPredicate(@wing int, @startTime datetime, @endTime datetime)
    RETURNS TABLE 
	WITH SCHEMABINDING
AS
    RETURN SELECT 1 AS accessResult FROM
        dbo.StaffDuties d INNER JOIN dbo.Employees e ON (d.EmpId = e.EmpId) 
    WHERE 
	(
		-- nurses can only access patients who overlap with their wing assignments
		IS_MEMBER('nurse') = 1
		AND e.databasePrincipalId = DATABASE_PRINCIPAL_ID() 
		AND @wing = d.Wing
		AND 
		( 
			d.endTime >= @startTime AND d.startTime <= ISNULL(@endTime, GETDATE())
		)
	) 
	OR 
	(
		-- doctors can see all patients
		IS_MEMBER('doctor') = 1
	)
go

CREATE SECURITY POLICY rls.PatientsSecurityPolicy 
	ADD FILTER PREDICATE rls.accessPredicate(wing, startTime, endTime) ON dbo.patients,
	ADD BLOCK PREDICATE rls.accessPredicate(wing, startTime, endTime) ON dbo.patients AFTER UPDATE
go

-- Impersonate various users in the system (for demo purposes)
EXECUTE ('SELECT * FROM patients;') AS USER = 'nurse_BartonC';       --3
EXECUTE ('SELECT * FROM patients;') AS USER = 'nurse_AllenM';        --4
EXECUTE ('SELECT * FROM patients;') AS USER = 'nurse_NightingaleF';  --2
EXECUTE ('SELECT * FROM patients;') AS USER = 'doctor_ApgarV';       --7
EXECUTE ('SELECT * FROM patients;') AS USER = 'doctor_CharcotJ';     --7
go

EXECUTE ('UPDATE patients SET Wing = 1 WHERE patientId = 6;') AS USER = 'nurse_BartonC' -- filtered, 0 rows affected
go
EXECUTE ('UPDATE patients SET Wing = 3 WHERE patientId = 1;') AS USER = 'nurse_BartonC' -- blocked from changing Wing to an unassigned one
go

-- Click 'Include Actual Execution Plan' in SSMS (Ctrl + M)
-- This will show how the query plan changes when RLS is enabled
ALTER SECURITY POLICY rls.PatientsSecurityPolicy WITH (STATE=OFF)
SELECT * FROM patients
go
ALTER SECURITY POLICY rls.PatientsSecurityPolicy WITH (STATE=ON)
SELECT * FROM patients
go

-- Monitor security policies and predicates using these system views
SELECT * FROM sys.security_policies
SELECT * FROM sys.security_predicates
go
