import { NotAvailable } from '../../design/Preview'
import { SectionHeader } from './parts'

export function ActivityTab() {
  return <div style={{ maxWidth: 760 }}>
    <SectionHeader title="Activity" description="Who changed what, and when." />
    <NotAvailable icon="activity" title="Activity log">An audit trail of configuration changes and access isn't recorded yet. Deploy history is on the Overview tab.</NotAvailable>
  </div>
}
