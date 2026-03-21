import { Shield } from 'lucide-react';
import { cn } from '@/utils/cn';
import type { ScanModule } from '@/types';

interface Props {
  module:    ScanModule;
  checked?:  boolean;
  onChange?: (checked: boolean) => void;
}

export function ModuleCard({ module, checked, onChange }: Props) {
  return (
    <label className={cn(
      'flex items-start gap-3 p-4 rounded-xl border cursor-pointer transition',
      checked
        ? 'border-violet bg-violet/5'
        : 'border-gray-200 hover:border-gray-300',
    )}>
      {onChange !== undefined && (
        <input
          type="checkbox"
          checked={checked}
          onChange={e => onChange(e.target.checked)}
          className="mt-1 accent-violet"
        />
      )}
      <div className="w-8 h-8 rounded-lg bg-navy flex items-center justify-center shrink-0">
        <Shield size={16} className="text-white" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="font-medium text-navy text-sm">{module.name}</p>
        <p className="text-xs text-gray-500 mt-0.5">{module.description}</p>
      </div>
      <span className={cn(
        'text-xs font-medium px-2 py-0.5 rounded-full shrink-0',
        module.isActive ? 'bg-success/10 text-success' : 'bg-gray-100 text-gray-500',
      )}>
        {module.isActive ? 'Actif' : 'Inactif'}
      </span>
    </label>
  );
}
