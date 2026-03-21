import { cn } from '@/utils/cn';
import type { Severity } from '@/types';

const styles: Record<Severity, string> = {
  CRITICAL: 'bg-coral/10    text-coral    border-coral/30',
  HIGH:     'bg-warning/10  text-warning  border-warning/30',
  MEDIUM:   'bg-violet/10   text-violet   border-violet/30',
  LOW:      'bg-success/10  text-success  border-success/30',
};

const labels: Record<Severity, string> = {
  CRITICAL: 'Critique',
  HIGH:     'Élevé',
  MEDIUM:   'Moyen',
  LOW:      'Faible',
};

interface Props {
  severity: Severity;
  size?: 'sm' | 'md';
}

export function SeverityBadge({ severity, size = 'md' }: Props) {
  return (
    <span className={cn(
      'inline-flex items-center rounded-full border font-medium font-mono',
      size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-xs',
      styles[severity],
    )}>
      {labels[severity]}
    </span>
  );
}
