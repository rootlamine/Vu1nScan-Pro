import { LucideIcon } from 'lucide-react';
import { cn } from '@/utils/cn';

interface Props {
  title: string;
  value: string | number;
  icon:  LucideIcon;
  color?: 'coral' | 'violet' | 'success' | 'warning' | 'gray';
}

const colorMap = {
  coral:   { bg: 'bg-coral/10',   icon: 'text-coral',   value: 'text-coral'   },
  violet:  { bg: 'bg-violet/10',  icon: 'text-violet',  value: 'text-violet'  },
  success: { bg: 'bg-success/10', icon: 'text-success', value: 'text-success' },
  warning: { bg: 'bg-warning/10', icon: 'text-warning', value: 'text-warning' },
  gray:    { bg: 'bg-gray-100',   icon: 'text-gray-500',value: 'text-navy'    },
};

export function StatCard({ title, value, icon: Icon, color = 'gray' }: Props) {
  const c = colorMap[color];
  return (
    <div className="bg-white rounded-2xl border border-gray-100 p-5 flex items-center gap-4">
      <div className={cn('w-12 h-12 rounded-xl flex items-center justify-center shrink-0', c.bg)}>
        <Icon size={22} className={c.icon} />
      </div>
      <div>
        <p className="text-xs text-gray-500 font-medium">{title}</p>
        <p className={cn('text-2xl font-bold font-mono mt-0.5', c.value)}>{value}</p>
      </div>
    </div>
  );
}
