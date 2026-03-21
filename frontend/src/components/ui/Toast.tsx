import { useEffect } from 'react';
import { CheckCircle, XCircle, X } from 'lucide-react';
import { cn } from '@/utils/cn';

export type ToastType = 'success' | 'error';

interface Props {
  message: string;
  type:    ToastType;
  onClose: () => void;
  duration?: number;
}

export function Toast({ message, type, onClose, duration = 3500 }: Props) {
  useEffect(() => {
    const t = setTimeout(onClose, duration);
    return () => clearTimeout(t);
  }, [duration, onClose]);

  return (
    <div className={cn(
      'fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-xl shadow-lg border',
      'animate-in slide-in-from-bottom-4 duration-200',
      type === 'success'
        ? 'bg-white border-success/30 text-success'
        : 'bg-white border-coral/30 text-coral',
    )}>
      {type === 'success'
        ? <CheckCircle size={18} />
        : <XCircle     size={18} />
      }
      <span className="text-sm font-medium text-navy">{message}</span>
      <button onClick={onClose} className="ml-2 text-gray-400 hover:text-gray-600">
        <X size={14} />
      </button>
    </div>
  );
}
