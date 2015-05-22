-- Row-Level Security: Blocking unauthorized INSERTs
-- -------------------------------------------------
-- This demo adds "blocking" functionality to the starter script in "Building More
-- Secure Middle-Tier Applications using Row-Level Security". We'll assume you're
-- already using the starter code from here:
-- https://rlssamples.codeplex.com/SourceControl/latest#RLS-Middle-Tier-Apps-Demo.sql
--
-- Although the security policy now filters results for "get" operations, there is 
-- nothing preventing our application from accidentally inserting or updating rows 
-- to belong to other tenants. We'll add check and default constraints to explicitly 
-- block this from happening and return an error, which will help us catch mistakes in 
-- our application code.

-- First we need to create a scalar version of our predicate function to use for our
-- check constraints (which don't allow subqueries)
CREATE FUNCTION rls.fn_tenantAccessPredicateScalar(@TenantId int)
	RETURNS bit
AS
	BEGIN
		IF EXISTS( SELECT 1 FROM rls.fn_tenantAccessPredicate(@TenantId) )
			RETURN 1
		RETURN 0
	END
go

-- Add this function as a check constraint on our Sales table
ALTER TABLE Sales
	WITH NOCHECK -- don't check data already in table
	ADD CONSTRAINT chk_blocking_Sales -- needs a unique name
	CHECK( rls.fn_tenantAccessPredicateScalar(TenantId) = 1 )
go

-- Now if we grant INSERT to AppUser (the shared application login), we can only 
-- INSERT rows that satisfy the predicate (i.e., belong to the current tenant).
GRANT INSERT ON Sales TO AppUser;
go
EXECUTE AS USER = 'AppUser' -- simulate app user
go
EXECUTE rls.sp_setContextInfoAsTenantId 2 -- tenant 2 is logged in
go
INSERT INTO Sales (OrderId,	SKU, Price, TenantId) VALUES (999, 'Movie999', 100, 1); -- fails: "The INSERT statement conflicted with CHECK constraint"
go
INSERT INTO Sales (OrderId,	SKU, Price, TenantId) VALUES (111, 'Movie111', 5, 2); -- succeeds because correct TenantId
go
SELECT * FROM Sales -- Movie111 has been inserted
go
EXECUTE rls.sp_setContextInfoAsTenantId 1 -- simulate tenant 1 logging in
go
SELECT * FROM Sales -- Movie999 has not been accidentally inserted
go
REVERT
go

-- Likewise for UPDATE: application cannot update the TenantId of any rows to a new value
GRANT UPDATE ON Sales TO AppUser;
go
EXECUTE AS USER = 'AppUser';
go
EXECUTE rls.sp_setContextInfoAsTenantId 2 -- tenant 2 is logged in
go
UPDATE Sales SET TenantId = 99 WHERE OrderID = 2 -- fails: "The UPDATE statement conflicted with CHECK constraint"
go
REVERT;
go

-- For additional application transparency, we'll add a default constraint on our Sales table
-- so that the TenantId is auto-populated with the current value of CONTEXT_INFO for INSERTs.
ALTER TABLE Sales
	ADD CONSTRAINT df_TenantId_Sales DEFAULT CONVERT(int, CONVERT(varbinary(4), CONTEXT_INFO())) FOR TenantId -- TenantId type is int (4 bytes)
go

-- Now the application doesn't have to specify the TenantId when inserting rows
EXECUTE AS USER = 'AppUser'
go
EXECUTE rls.sp_setContextInfoAsTenantId 2
go
INSERT INTO Sales (OrderId,	SKU, Price) VALUES (102, 'Movie222', 5); -- don't specify TenantId
go
SELECT * FROM Sales -- Movie222 has been inserted for TenantId = 2
go
REVERT
go
