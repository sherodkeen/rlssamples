
-- Let's create a new function that continues filtering as before when CONTEXT_INFO is set, 
-- but allows a call without CONTEXT_INFO set to see all rows.
-- Note that on Azure SQL Database, CONTEXT_INFO returns a unique connection GUID (not null)
-- if it has not been set, so you must execute SET CONTEXT_INFO 0x to reset it to null.
--
CREATE FUNCTION [rls].[fn_userAccessPredicate_with_superuser](@TenantId int) 
RETURNS TABLE 
WITH SCHEMABINDING 
AS
	RETURN SELECT 1 AS fn_accessResult 
		WHERE DATABASE_PRINCIPAL_ID() = DATABASE_PRINCIPAL_ID ('AppUser')
		AND 
		( CONVERT(int, CONVERT( varbinary(4), CONTEXT_INFO())) = @TenantId 
		OR CONTEXT_INFO() is null )
GO 
 
-- Modify the existing Security Policy and replace the predciate function with the new one
 ALTER SECURITY POLICY [rls].[tenantAccessPolicy] 
	 ALTER FILTER PREDICATE [rls].[fn_userAccessPredicate_with_superuser]([TenantId]) on [dbo].[Sales]
 GO 


-- 
-- Grant SHOWPLAN permission to the AppUser in order to analyze the query plan
GRANT SHOWPLAN TO [AppUser]
GO

-- Try to compare the performance to the previous predicate
EXECUTE AS USER = 'AppUser'
go
EXECUTE [rls].[sp_setContextInfoAsTenantId] 1
GO
SET SHOWPLAN_ALL ON
GO
SELECT * FROM Sales
GO
SET SHOWPLAN_ALL OFF
GO
REVERT
GO

-- Since the new predicate is not working as we originally expected, we will revert to the previous one while we resolve the problem.
-- This will allow to continue working uninterrupted with the old behavior while we solve the performance issue from teh new predicate
--
ALTER SECURITY POLICY [rls].[tenantAccessPolicy]
	ALTER FILTER PREDICATE [rls].[fn_tenantAccessPredicate](TenantId) ON dbo.Sales
GO

-- Create function that will help us to transform the predicate into a ranged predicate

-- If context_info is not set, return MIN_INT, otherwise return context_info value as int
 CREATE FUNCTION [rls].[int_lo]() RETURNS int
 WITH SCHEMABINDING
 AS BEGIN
 RETURN CASE WHEN context_info() is null THEN -2147483648 ELSE convert(int, convert(varbinary(4), context_info())) END
 END
 GO
 
 -- If context_info is not set, return MAX_INT, otherwise return context_info value as int
 CREATE FUNCTION [rls].[int_hi]() RETURNS int
 WITH SCHEMABINDING
 AS BEGIN
 RETURN CASE WHEN context_info() is null THEN 2147483647 ELSE convert(int, convert(varbinary(4), context_info())) END
 END
 GO

-- Now rewrite the predicate
 ALTER FUNCTION [rls].[fn_userAccessPredicate_with_superuser](@TenantId int) 
 RETURNS TABLE 
 WITH SCHEMABINDING 
 AS 
 RETURN SELECT 1 AS fn_accessResult 
 WHERE DATABASE_PRINCIPAL_ID() = DATABASE_PRINCIPAL_ID ('AppUser') -- the shared application login
 AND 
 -- tenant info within the range:
 -- If context_info is set, the range will point only to one value
 -- If context_info is not set, the range will include all values
 @TenantId BETWEEN [rls].[int_lo]() AND [rls].[int_hi]() 
 GO 
 
 -- Replace the predicate with the newly written one
 ALTER SECURITY POLICY [rls].[tenantAccessPolicy] 
 ALTER FILTER PREDICATE [rls].[fn_userAccessPredicate_with_superuser]([TenantId]) on [dbo].[Sales]
 GO 

-- Try to compare the performance to the previous predicate
-- As expected, there will be a seek that will help for the normal (context_info set) case performance
EXECUTE AS USER = 'AppUser'
go
EXECUTE [rls].[sp_setContextInfoAsTenantId] 1
GO
SET SHOWPLAN_ALL ON
GO
SELECT * FROM Sales -- WITH(FORCESEEK)
GO
SET SHOWPLAN_ALL OFF
GO
REVERT
GO

-- 
-- Revoke SHOWPLAN permission to the AppUser in order to analyze the query plan
REVOKE SHOWPLAN TO [AppUser]
GO
