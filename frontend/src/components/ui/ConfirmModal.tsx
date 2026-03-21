import { AlertTriangle } from 'lucide-react';

interface Props {
  isOpen:    boolean;
  title?:    string;
  message:   string;
  confirmLabel?: string;
  onConfirm: () => void;
  onCancel:  () => void;
  loading?:  boolean;
}

export function ConfirmModal({
  isOpen, title = 'Confirmer', message, confirmLabel = 'Supprimer',
  onConfirm, onCancel, loading = false,
}: Props) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Overlay */}
      <div
        className="absolute inset-0 bg-navy/40 backdrop-blur-sm"
        onClick={onCancel}
      />
      {/* Boîte */}
      <div className="relative bg-white rounded-2xl shadow-xl p-6 w-full max-w-md mx-4">
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 rounded-full bg-coral/10 flex items-center justify-center shrink-0">
            <AlertTriangle size={20} className="text-coral" />
          </div>
          <div>
            <h3 className="font-semibold text-navy text-lg">{title}</h3>
            <p className="text-gray-500 text-sm mt-1">{message}</p>
          </div>
        </div>
        <div className="flex gap-3 mt-6 justify-end">
          <button
            onClick={onCancel}
            disabled={loading}
            className="px-4 py-2 text-sm font-medium text-gray-600 bg-gray-100 rounded-xl hover:bg-gray-200 transition"
          >
            Annuler
          </button>
          <button
            onClick={onConfirm}
            disabled={loading}
            className="px-4 py-2 text-sm font-medium text-white bg-coral rounded-xl hover:bg-opacity-90 transition disabled:opacity-50"
          >
            {loading ? 'Suppression...' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
