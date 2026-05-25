import AuditLogPanel from '../components/AuditLogPanel';
import { useAuth } from '../hooks/useAuth';

/**
 * Audit page — admin-only view onto the paginated audit log.
 *
 * {@link AuditLogPanel} itself renders an empty placeholder when the caller is
 * not an admin; this wrapper just forwards the role so the placeholder text
 * stays consistent.
 */
export function AuditPage() {
  const auth = useAuth();
  const isAdmin = auth.roles?.includes('ADMIN') ?? false;
  return (
    <div className="h-full overflow-auto">
      <AuditLogPanel isAdmin={isAdmin} />
    </div>
  );
}
