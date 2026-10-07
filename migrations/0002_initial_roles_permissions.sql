-- Migration 0002: Built-in Roles and Permissions

-- Insert Permissions
INSERT OR IGNORE INTO permissions (id, code, description) VALUES
('perm_user_read', 'user.read', 'View users'),
('perm_user_create', 'user.create', 'Create users'),
('perm_user_update', 'user.update', 'Update users'),
('perm_user_disable', 'user.disable', 'Disable/enable users'),
('perm_group_read', 'group.read', 'View groups'),
('perm_group_write', 'group.write', 'Manage groups and memberships'),
('perm_asset_read', 'asset.read', 'View assets and asset groups'),
('perm_asset_create', 'asset.create', 'Create assets and asset groups'),
('perm_asset_update', 'asset.update', 'Update assets and asset groups'),
('perm_asset_delete', 'asset.delete', 'Delete assets and asset groups'),
('perm_cred_create', 'credential.create', 'Create credentials and accounts'),
('perm_cred_replace', 'credential.replace', 'Replace credentials secrets'),
('perm_cred_delete', 'credential.delete', 'Delete credentials and accounts'),
('perm_auth_read', 'authorization.read', 'View asset authorization rules'),
('perm_auth_write', 'authorization.write', 'Create and modify asset authorization rules'),
('perm_sess_view_own', 'session.view_own', 'View own sessions and connect to authorized assets'),
('perm_sess_view_all', 'session.view_all', 'View all active and historical sessions'),
('perm_sess_monitor', 'session.monitor', 'Live monitor active sessions in read-only mode'),
('perm_sess_terminate', 'session.terminate', 'Force terminate active sessions'),
('perm_audit_read', 'audit.read', 'View audit logs and session recordings'),
('perm_settings_read', 'settings.read', 'View system settings'),
('perm_settings_write', 'settings.write', 'Modify system settings');

-- Insert Built-in Roles
INSERT OR IGNORE INTO roles (id, name, description, is_builtin, created_at) VALUES
('role_super_admin', 'Super Admin', 'Full administrative access to all bastion features', 1, 1760000000),
('role_asset_admin', 'Asset Admin', 'Manage assets, accounts, credentials, and access rules', 1, 1760000000),
('role_security_auditor', 'Security Auditor', 'Audit sessions, monitor live connections, and inspect logs', 1, 1760000000),
('role_user', 'User', 'Standard user with access only to explicitly authorized assets', 1, 1760000000);

-- Role Permissions: Super Admin (All Permissions)
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT 'role_super_admin', id FROM permissions;

-- Role Permissions: Asset Admin (asset.*, credential.*, authorization.*)
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT 'role_asset_admin', id FROM permissions 
WHERE code LIKE 'asset.%' OR code LIKE 'credential.%' OR code LIKE 'authorization.%';

-- Role Permissions: Security Auditor (session.view_all, session.monitor, audit.read)
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT 'role_security_auditor', id FROM permissions 
WHERE code IN ('session.view_all', 'session.monitor', 'audit.read');

-- Role Permissions: User (session.view_own)
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT 'role_user', id FROM permissions 
WHERE code IN ('session.view_own');
