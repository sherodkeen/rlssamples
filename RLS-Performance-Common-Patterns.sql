-- Row-Level Security: Performance and common patterns
-- ---------------------------------------------------
-- This sample demonstrates three common patterns for implementing RLS
-- predicates. In addition, we'll show how RLS has performance comparable to
-- what you'd get with view-based workarounds for row-level filtering.
--
-- For each pattern, we'll create an RLS predicate and policy, as well as
-- an equivalent view. Then, we'll query the Sales table and compare the 
-- Actual Query Plans.

-- Start by creating a sample schema, with indexes on our lookup columns
CREATE TABLE Sales (
	OrderId int identity(1,1) primary key,
    ItemId int,
    Price decimal,
    SalesRepId int,
    Region nvarchar(50),
	Date date
)
go

CREATE NONCLUSTERED INDEX IX_Sales_SalesRepId ON Sales(SalesRepId)
go

CREATE NONCLUSTERED INDEX IX_Sales_Region ON Sales(Region)
go

CREATE NONCLUSTERED INDEX IX_Sales_Date ON Sales(Date)
go

CREATE TABLE DateAssignments (
	SalesRepId int,
	StartDate date,
	EndDate date
)
go

CREATE TABLE RegionAssignments (
	SalesRepId int,
	Region nvarchar(50)
)
go

-- Populate with dummy data
-- The Sales table will get 50k rows of random data
INSERT INTO DateAssignments (SalesRepId, StartDate, EndDate)
	VALUES  (1, '2014-09-01', '2014-12-31'),
			(2, '2015-01-01', '2015-04-01'),
			(3, '2014-02-01', '2015-04-01')
go

INSERT INTO RegionAssignments (SalesRepId, Region)
	VALUES	(1, 'North America'),
			(2, 'Europe'),
			(3, 'Europe'),
			(3, 'Asia')
go

DECLARE @Start date = '2014-09-01';
DECLARE @End date = '2015-04-01';
DECLARE @i int = 1;
WHILE @i < 50001
BEGIN
	DECLARE @t date = dateadd(day, 
               rand(checksum(newid()))*(1+datediff(day, @Start, @End)), @Start);
	IF @i % 3 = 0 
		INSERT INTO Sales (ItemId, Price, SalesRepId, Region, Date)
			VALUES (@i % 20, 25 * @i % 14, @i % 10 + 1, N'North America', @t);
	ELSE IF @i % 3 = 1 
		INSERT INTO Sales (ItemId, Price, SalesRepId, Region, Date)
			VALUES (@i % 20, 25 * @i % 14, @i % 10 + 1, N'Europe', @t);
	ELSE
		INSERT INTO Sales (ItemId, Price, SalesRepId, Region, Date)
			VALUES (@i % 20, 25 * @i % 14, @i % 10 + 1, N'Asia', @t);
	SET @i = @i + 1;
END    
go

SELECT COUNT(*) FROM Sales
go

-- Create a separate schema for our RLS objects
CREATE SCHEMA rls
go

-- In practice, a mid-tier application would set CONTEXT_INFO to the
-- ID of the current user
SET CONTEXT_INFO 3
go

-- ------------------------------------------
-- Pattern 1: Rows assigned directly to users
-- ------------------------------------------
CREATE FUNCTION rls.staffAccessPredicateA(@SalesRepId int)
	RETURNS TABLE
	WITH SCHEMABINDING
AS
	RETURN SELECT 1 AS accessResult 
		WHERE CONVERT(int, CONVERT(varbinary(4), CONTEXT_INFO())) = @SalesRepId -- @SalesRepId (int) is 4 bytes
go

CREATE SECURITY POLICY rls.staffPolicyA
	ADD FILTER PREDICATE rls.staffAccessPredicateA(SalesRepId) ON dbo.Sales
go

CREATE VIEW vw_SalesA
AS
	SELECT * FROM Sales
		WHERE CONVERT(int, CONVERT(varbinary(4), CONTEXT_INFO())) = SalesRepId -- SalesRepId (int) is 4 bytes
go


-- Check execution plans (enable Actual Execution Plan before executing these)
ALTER SECURITY POLICY rls.staffPolicyA WITH (STATE=ON)
go
SELECT * FROM Sales
go
ALTER SECURITY POLICY rls.staffPolicyA WITH (STATE=OFF)
go
SELECT * FROM vw_SalesA
go


-- --------------------------------------------
-- Pattern 2: Row assignments in a lookup table
-- --------------------------------------------
CREATE FUNCTION rls.staffAccessPredicateB(@Region nvarchar(50))
	RETURNS TABLE
	WITH SCHEMABINDING
AS
	RETURN SELECT 1 AS accessResult FROM dbo.RegionAssignments
		WHERE CONVERT(int, CONVERT(varbinary(4), CONTEXT_INFO())) = SalesRepId
		AND Region = @Region
go

CREATE SECURITY POLICY rls.staffPolicyB
	ADD FILTER PREDICATE rls.staffAccessPredicateB(Region) ON dbo.Sales
go

CREATE VIEW vw_SalesB
AS
	SELECT Sales.* FROM Sales, RegionAssignments
		WHERE CONVERT(int, CONVERT(varbinary(4), CONTEXT_INFO())) = RegionAssignments.SalesRepId
		AND Sales.Region = RegionAssignments.Region
go

-- Check execution plans
ALTER SECURITY POLICY rls.staffPolicyB WITH (STATE=ON)
go
SELECT * FROM Sales
go

ALTER SECURITY POLICY rls.staffPolicyB WITH (STATE=OFF)
go
SELECT * FROM vw_SalesB
go

-- --------------------------------------
-- Pattern 3: Row assignments from a JOIN
-- --------------------------------------
CREATE FUNCTION rls.staffAccessPredicateC(@Region nvarchar(50), @Date date)
	RETURNS TABLE
	WITH SCHEMABINDING
AS
	RETURN SELECT 1 AS accessResult FROM dbo.RegionAssignments ra
		INNER JOIN dbo.DateAssignments da ON ra.SalesRepId = da.SalesRepId
			WHERE CONVERT(int, CONVERT(varbinary(4), CONTEXT_INFO())) = ra.SalesRepId
			AND @Region = ra.Region
			AND @Date >= da.StartDate
			AND @Date <= da.EndDate
go

CREATE SECURITY POLICY rls.staffPolicyC
	ADD FILTER PREDICATE rls.staffAccessPredicateC(Region, Date) ON dbo.Sales
go

drop view vw_SalesC
CREATE VIEW vw_SalesC
AS
	SELECT Sales.* FROM Sales
		WHERE EXISTS (
			SELECT 1 AS accessResult FROM RegionAssignments ra
			INNER JOIN DateAssignments da on ra.SalesRepId = da.SalesRepId
				WHERE CONVERT(int, CONVERT(varbinary(4), CONTEXT_INFO())) = ra.SalesRepId
				AND Sales.Region = ra.Region
				AND Sales.Date >= da.StartDate
				AND Sales.Date <= da.EndDate
		)
go

-- Check execution plans
ALTER SECURITY POLICY rls.staffPolicyC WITH (STATE=ON)
go
SELECT * FROM Sales
go

ALTER SECURITY POLICY rls.staffPolicyC WITH (STATE=OFF)
go
SELECT * FROM vw_SalesC
go
