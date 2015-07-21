-- Tuning RLS predicates with Query Store
-- --------------------------------------
-- This sample shows how Query Store can help to tune the performance of RLS predicates.
-- We'll use the AdventureWorks2014 database, downloadable here: https://msftdbprodsamples.codeplex.com/releases/view/125550

-- INITIAL SETUP FOR DEMO PURPOSES
-- AdventureWorks comes with a few indexes included, but for this demo we want to start from scratch
-- So we'll drop all nonclustered indexes on the Employee, SalesOrderHeader, and SalesOrderDetail tables to have a clean slate for testing
-- Then we'll see which ones are most important to the performance of our workload with RLS
DROP INDEX AK_Employee_LoginID ON HumanResources.Employee
DROP INDEX AK_Employee_NationalIDNumber ON HumanResources.Employee
DROP INDEX AK_Employee_rowguid ON HumanResources.Employee
DROP INDEX IX_Employee_OrganizationLevel_OrganizationNode ON HumanResources.Employee
DROP INDEX IX_Employee_OrganizationNode ON HumanResources.Employee
DROP INDEX AK_SalesOrderHeader_rowguid ON Sales.SalesOrderHeader
DROP INDEX AK_SalesOrderHeader_SalesOrderNumber ON Sales.SalesOrderHeader
DROP INDEX IX_SalesOrderHeader_CustomerID ON Sales.SalesOrderHeader
DROP INDEX IX_SalesOrderHeader_SalesPersonID ON Sales.SalesOrderHeader
DROP INDEX AK_SalesOrderDetail_rowguid ON Sales.SalesOrderDetail
DROP INDEX IX_SalesOrderDetail_ProductID ON Sales.SalesOrderDetail
go

SELECT * FROM sys.indexes WHERE object_id in (object_id('Sales.SalesOrderHeader'), object_id('Sales.SalesOrderDetail'), object_id('HumanResources.Employee'))
go

-- ENABLE ROW-LEVEL SECURITY
-- These employees are the salespeople
SELECT e.* FROM HumanResources.Employee e INNER JOIN Sales.SalesPerson sp ON e.BusinessEntityID = sp.BusinessEntityID
go

-- Salespeople should only be able to see orders assigned to them, or assigned to people who report to them
SELECT * FROM Sales.SalesOrderHeader -- 31465 rows total
SELECT * FROM Sales.SalesOrderDetail -- 121317 rows total
go

-- Create a few test users (salespeople) for the demo
CREATE USER stephen0 WITHOUT LOGIN -- North American Sales Manager (hierarchyid = /6/1/)
CREATE USER david8 WITHOUT LOGIN -- regular salesperson (hierarchyid = /6/1/9/)
CREATE USER amy0 WITHOUT LOGIN -- European Sales Manager (hierarchyid = /6/3/)
CREATE USER rachel0 WITHOUT LOGIN -- regular salesperson (hierarchyid = /6/3/1/)

GRANT SELECT ON Sales.SalesOrderHeader TO stephen0, david8, amy0, rachel0
GRANT SELECT ON Sales.SalesOrderDetail TO stephen0, david8, amy0, rachel0
go

-- Create RLS objects
CREATE SCHEMA rls
go

CREATE FUNCTION rls.salesPersonPredicate(@SalesPersonID int)
	RETURNS TABLE
	WITH SCHEMABINDING
AS
	-- only see orders assigned to you, or assigned to salespeople who report to you
	RETURN SELECT 1 AS accessResult
	FROM HumanResources.Employee e1
	INNER JOIN HumanResources.Employee e2
		ON e2.OrganizationNode.IsDescendantOf(e1.OrganizationNode) = 1
	WHERE e1.LoginID = 'adventure-works\' + USER_NAME()
	AND e2.BusinessEntityID = @SalesPersonID
go

CREATE FUNCTION rls.salesPersonPredicate_LookupSalesPerson(@SalesOrderID int)
	RETURNS TABLE
	WITH SCHEMABINDING
AS
	-- only see orders assigned to you, or assigned to salespeople who report to you
	-- (note: need to look up the order's assigned SalesPersonID in SalesOrderHeader)
	RETURN SELECT 1 AS accessResult
	FROM HumanResources.Employee e1
	INNER JOIN HumanResources.Employee e2
		ON e2.OrganizationNode.IsDescendantOf(e1.OrganizationNode) = 1
	INNER JOIN Sales.SalesOrderHeader soh 
		ON e2.BusinessEntityID = soh.SalesPersonID
	WHERE e1.LoginID = 'adventure-works\' + USER_NAME()
	AND soh.SalesOrderID = @SalesOrderID
go

CREATE SECURITY POLICY rls.salesPersonPolicy
	ADD FILTER PREDICATE rls.salesPersonPredicate(SalesPersonID) ON Sales.SalesOrderHeader,
	ADD FILTER PREDICATE rls.salesPersonPredicate_LookupSalesPerson(SalesOrderID) ON Sales.SalesOrderDetail
go

-- Sanity check that the predicate is working
EXECUTE AS USER = 'stephen0' -- North American Sales Manager (hierarchyid = /6/1/)
SELECT * FROM Sales.SalesOrderHeader -- 2989 rows, assigned to stephen0 or his reports lower in the hierarchy
SELECT * FROM Sales.SalesOrderDetail -- 46680 rows, details for stephen0's or his reports' orders
REVERT
go

EXECUTE AS USER = 'david8' -- regular salesperson (hierarchyid = /6/1/9/)
SELECT * FROM Sales.SalesOrderHeader -- 189 rows, assigned to david8
SELECT * FROM Sales.SalesOrderDetail -- 2247 rows, details for david8's orders
REVERT
go

-- Create an example workload with a 'critical query' that gets the most-sold products
-- Note that the security policy restricts this to orders assigned to you, or to your reports
CREATE PROC sp_get_top_products
AS
	SELECT TOP 10 p.Name, SUM(sod.OrderQty) AS TotalOrders
	FROM Sales.SalesOrderDetail sod
	INNER JOIN Production.Product p ON p.ProductID = sod.ProductID
	GROUP BY p.Name 
	ORDER BY TotalOrders DESC
go

GRANT EXECUTE ON sp_get_top_products TO stephen0, david8, amy0, rachel0
go

EXECUTE AS USER = 'david8'
EXEC sp_get_top_products
REVERT
go


-- PERFORMANCE TUNING
-- Turn on Query Store, or clear the cache if it was on already
ALTER DATABASE AdventureWorks2014 SET QUERY_STORE=ON
go
ALTER DATABASE AdventureWorks2014 SET QUERY_STORE (INTERVAL_LENGTH_MINUTES = 1, QUERY_CAPTURE_MODE = AUTO)
go
ALTER DATABASE AdventureWorks2014 SET QUERY_STORE CLEAR
go

-- Simulate a workload by looping through our sp_get_top_products query a few times as an example user
EXECUTE AS USER = 'david8'
DECLARE @i int = 0
WHILE (@i < 100)
BEGIN
	EXEC sp_get_top_products;
	SET @i = @i + 1;
END
REVERT
go

-- In the SSMS Object Explorer, look at Query Store > Top Resource Consuming Queries
-- Our query (query_id = 1, because it's the first one we ran after clearing the cache) has a recommendation to create an index on Sales.SalesOrderHeader(SalesPersonID)
-- Does this recommendation actually help? How much?
-- We can evaluate the performance difference by creating the index, simulating the workload again, and then comparing the performance using Query Store
WAITFOR DELAY '00:01:00' -- to make sure we're in a new Query Store aggregation interval
go
CREATE NONCLUSTERED INDEX IX_SalesOrderHeader_SalesPersonID ON Sales.SalesOrderHeader (SalesPersonID)
go
EXECUTE AS USER = 'david8'
DECLARE @i int = 0
WHILE (@i < 100)
BEGIN
	EXEC sp_get_top_products;
	SET @i = @i + 1;
END
REVERT
go

-- Refresh the Top Resource Consuming Queries again: the visualization of query performance shows the improvement
-- Or you can also use the Query Store DMVs programmatically to compare the difference (below)
SELECT p.plan_id, q.query_id, qt.query_text_id, qt.query_sql_text, p.query_plan,
	RANK() OVER (ORDER BY MIN(rs.first_execution_time) ASC) AS execution_order, -- identify plans by the order in which we ran them
    SUM(rs.count_executions) AS total_execution_count, 
	AVG(rs.avg_duration) AS avg_avg_duration, -- 'average average' because Query Store already aggregates at a smaller interval
	MIN(rs.min_duration) AS min_duration,
	MAX(rs.max_duration) AS max_duration,
	AVG(rs.avg_cpu_time) AS avg_avg_cpu_time,
	AVG(rs.avg_logical_io_reads) AS avg_avg_logical_io_reads,
	AVG(rs.avg_physical_io_reads) AS avg_avg_physical_io_reads
FROM sys.query_store_query_text AS qt 
JOIN sys.query_store_query AS q 
    ON qt.query_text_id = q.query_text_id 
JOIN sys.query_store_plan AS p 
    ON q.query_id = p.query_id 
JOIN sys.query_store_runtime_stats AS rs 
    ON p.plan_id = rs.plan_id
WHERE qt.query_sql_text LIKE 'SELECT TOP 10 p.Name%' -- only show our query
GROUP BY p.plan_id, p.query_plan, q.query_id, qt.query_text_id, qt.query_sql_text
ORDER BY execution_order ASC;

-- We can test the performance impact of other changes using the same methods
-- For example, you might hypothesize that adding indexes on other columns used by the predicate function could further improve performance.
-- In particular, the two index seeks in the current query plan suggest the following:
--		CREATE UNIQUE NONCLUSTERED INDEX AK_Employee_LoginID ON HumanResources.Employee(LoginID ASC)
--		CREATE NONCLUSTERED INDEX IX_Employee_OrganizationNode ON HumanResources.Employee(OrganizationNode ASC)
-- 
-- Let's try both:
WAITFOR DELAY '00:01:00' -- to make sure we're in a new Query Store aggregation interval
go

CREATE UNIQUE NONCLUSTERED INDEX AK_Employee_LoginID ON HumanResources.Employee(LoginID)
go
EXECUTE AS USER = 'david8'
DECLARE @i int = 0
WHILE (@i < 100)
BEGIN
	EXEC sp_get_top_products;
	SET @i = @i + 1;
END
REVERT
go

WAITFOR DELAY '00:01:00' -- to make sure we're in a new Query Store aggregation interval
go

CREATE NONCLUSTERED INDEX IX_Employee_OrganizationNode ON HumanResources.Employee(OrganizationNode)
go
EXECUTE AS USER = 'david8'
DECLARE @i int = 0
WHILE (@i < 100)
BEGIN
	EXEC sp_get_top_products;
	SET @i = @i + 1;
END
REVERT
go

-- Now you can observe the results again using either the Top Resource Consuming Queries or DMVs