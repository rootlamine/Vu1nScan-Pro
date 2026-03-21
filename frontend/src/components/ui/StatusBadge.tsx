import { cn } from '@/utils/cn';
import type { ScanStatus } from '@/types';

const styles: Record<ScanStatus, string> = {
  PENDING:   'bg-gray-100   text-gray-600  border-gray-200',
  RUNNING:   'bg-violet/10  text-violet    border-violet/30',
  COMPLETED: 'bg-success/10 text-success   border-success/30',
  FAILED:    'bg-coral/10   text-coral     border-coral/30',
};

const labels: Record<ScanStatus, string> = {
  PENDING:   'En attente',
  RUNNING:   'En cours',
  COMPLETED: 'Terminé',
  FAILED:    'Échoué',
};

interface Props {
  status: ScanStatus;
  size?: 'sm' | 'md';
}

export function StatusBadge({ status, size = 'md' }: Props) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1.5 rounded-full border font-medium',
      size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-xs',
      styles[status],
    )}>
      {status === 'RUNNING' && (
        <span className="w-1.5 h-1.5 rounded-full bg-violet animate-pulse" />
      )}
      {labels[status]}
    </span>
  );
}
