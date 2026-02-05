-- Initial database setup script
-- This runs automatically when the PostgreSQL container starts for the first time

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant permissions (user is already created by Docker)
GRANT ALL PRIVILEGES ON DATABASE soc_iot_db TO soc_toolkit;

-- Create schema if needed
CREATE SCHEMA IF NOT EXISTS public;
GRANT ALL ON SCHEMA public TO soc_toolkit;
