import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { getActionsForEntityType, ActionSchema } from '@/lib/actionRegistry';
import { useToast } from '@/components/ui/Toast';
import { ShieldAlert, Check } from 'lucide-react';

interface QuickActionsProps {
  entityType: string;
  entityId: string;
  className?: string;
  orientation?: 'horizontal' | 'vertical';
}

export function QuickActions({ entityType, entityId, className = '', orientation = 'horizontal' }: QuickActionsProps) {
  const actions = getActionsForEntityType(entityType);
  const [activeAction, setActiveAction] = useState<string | null>(null);
  const [confirmingAction, setConfirmingAction] = useState<ActionSchema | null>(null);
  const { toast } = useToast();

  if (actions.length === 0) return null;

  const handleActionClick = (action: ActionSchema) => {
    if (action.requiresApproval) {
      setConfirmingAction(action);
    } else {
      executeAction(action);
    }
  };

  const executeAction = async (action: ActionSchema) => {
    setActiveAction(action.id);
    try {
      const token = typeof window !== 'undefined' ? localStorage.getItem('sentinel_token') : null;
      const res = await fetch('/api/proxy/api/v1/soar/execute-container', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          capability: action.id,
          context: {
            entity_id: entityId,
            entity_type: entityType,
          }
        })
      });

      if (res.ok) {
        toast(`Action "${action.name}" successfully dispatched for ${entityId}`, 'success');
      } else {
        const err = await res.json().catch(() => ({}));
        toast(`Action failed: ${err.detail || res.statusText}`, 'error');
      }
    } catch (error) {
      toast('Network error during action dispatch', 'error');
    } finally {
      setActiveAction(null);
      setConfirmingAction(null);
    }
  };

  return (
    <div className={`relative flex gap-1 ${orientation === 'vertical' ? 'flex-col' : 'flex-row'} ${className}`}>
      {actions.map((action) => {
        const Icon = action.icon;
        const isExecuting = activeAction === action.id;
        
        let hoverClass = 'hover:bg-ng-mid hover:text-ng-cyan border-transparent hover:border-ng-outline-dim/40';
        if (action.severity === 'high') hoverClass = 'hover:bg-ng-error/10 hover:text-ng-error border-transparent hover:border-ng-error/50';

        return (
          <button
            key={action.id}
            title={action.description}
            onClick={(e) => {
              e.stopPropagation();
              handleActionClick(action);
            }}
            disabled={activeAction !== null}
            className={`group relative p-1.5 flex items-center justify-center rounded transition-all border ${hoverClass} ${
              isExecuting ? 'opacity-50 cursor-not-allowed' : ''
            }`}
          >
            {isExecuting ? (
              <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
                <Icon className="w-3.5 h-3.5 text-ng-muted" />
              </motion.div>
            ) : (
              <Icon className="w-3.5 h-3.5 text-ng-muted group-hover:text-current transition-colors" />
            )}
          </button>
        );
      })}

      <AnimatePresence>
        {confirmingAction && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: orientation === 'vertical' ? 0 : 5, x: orientation === 'vertical' ? -5 : 0 }}
            animate={{ opacity: 1, scale: 1, y: 0, x: 0 }}
            exit={{ opacity: 0, scale: 0.95 }}
            className={`absolute z-10 p-2 bg-ng-mid border border-ng-outline-dim/40  rounded text-xs w-48 ${
              orientation === 'vertical' ? 'right-full mr-2 top-0' : 'bottom-full mb-2 right-0'
            }`}
          >
            <div className="flex items-center gap-2 text-ng-error mb-2 font-bold font-mono">
              <ShieldAlert className="w-3.5 h-3.5" />
              Confirm Action
            </div>
            <p className="text-[10px] text-ng-muted leading-tight mb-2">
              Execute <span className="text-ng-on font-bold">{confirmingAction.name}</span> on <span className="font-mono">{entityId}</span>?
            </p>
            <div className="flex justify-end gap-2">
              <button 
                onClick={(e) => { e.stopPropagation(); setConfirmingAction(null); }}
                className="px-2 py-1 bg-ng-base border border-ng-outline-dim/40 hover:bg-ng-base/80 text-ng-on text-[10px]"
              >
                Cancel
              </button>
              <button 
                onClick={(e) => { e.stopPropagation(); executeAction(confirmingAction); }}
                className="flex items-center gap-1 px-2 py-1 bg-ng-error/20 border border-ng-error/50 hover:bg-ng-error/30 text-ng-error font-bold text-[10px]"
              >
                <Check className="w-3 h-3" /> Approve
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
