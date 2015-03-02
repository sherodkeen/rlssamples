-- Building more secure middle-tier applications using Row-Level Security
-- ----------------------------------------------------------------------
-- This simple demo shows how to create a security policy that filters
-- rows based on the current value of CONTEXT_INFO.
--
-- We'll assume you've created and connected to an empty V12 database.

CREATE TABLE dbo.Sales (
	OrderId int,
	SKU nvarchar(50),
	Price int,
	TenantId int)
GO

INSERT INTO Sales VALUES
	(1, 'Book001', 10, 1),
	(2, 'Movie001', 15, 2),
	(3, 'Movie002', 12, 2)
GO

SELECT * FROM Sales
GO

-- Create the shared application user, without login to simplify the demo
CREATE USER AppUser WITHOUT LOGIN 
GRANT SELECT ON Sales TO AppUser
GO

-- Create a separate schema for our RLS Security Policies and filter predicate functions.
-- This is a best practice for limiting access permissions to the RLS objects.
CREATE SCHEMA rls
GO

-- Create a stored procedure that our middle-tier application can use to set CONTEXT_INFO to a TenantId
CREATE PROCEDURE rls.sp_setContextInfoAsTenantId(@TenantId int)
AS
	SET CONTEXT_INFO @TenantId -- note: cannot be null
GO

GRANT EXECUTE ON rls.sp_setContextInfoAsTenantId TO AppUser
GO

-- Create an inline table-valued function (our filter predicate) that will only return rows where 
-- @TenantId = CONTEXT_INFO. If CONTEXT_INFO has not been set, we return all rows by default.
-- Note that we do all type conversions on CONTEXT_INFO to maximize performance.
CREATE FUNCTION rls.fn_tenantAccessPredicate(@TenantId int)
	RETURNS TABLE
	WITH SCHEMABINDING
AS
	RETURN SELECT 1 AS fn_accessResult 
		WHERE DATABASE_PRINCIPAL_ID() = DATABASE_PRINCIPAL_ID ('AppUser') -- the shared application login
		AND CONVERT(int, CONVERT(varbinary(4), CONTEXT_INFO())) = @TenantId -- @TenantId (int) is 4 bytes
GO

-- Create an index on the column we will use for the filter in order to improve performance
CREATE CLUSTERED INDEX IX_Sales_TenantId
    ON dbo.Sales(TenantId); 
GO

-- Create and enable a Security Policy that binds the predicate function to the Sales table
CREATE SECURITY POLICY rls.tenantAccessPolicy
	ADD FILTER PREDICATE rls.fn_tenantAccessPredicate(TenantId) ON dbo.Sales
GO

-- Impersonate the application for demo purposes
EXECUTE AS USER = 'AppUser'
go

-- Since we haven't set the CONTEXT_INFO to anything, we can not see any rows by default
SELECT * FROM Sales -- no rows
GO

-- After the app sets CONTEXT_INFO, rows are filtered based on the TenantId
EXECUTE rls.sp_setContextInfoAsTenantId 1
GO
SELECT * FROM Sales -- only Book001
GO

EXECUTE rls.sp_setContextInfoAsTenantId 2
GO
SELECT * FROM Sales -- only Movie001 and Movie002
GO

REVERT
go