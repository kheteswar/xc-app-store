import { useState, useMemo } from 'react';
import {
  LogIn,
  Pencil,
  Trash2,
  Server,
  Clock,
  AlertTriangle,
  Activity,
  ShieldAlert,
} from 'lucide-react';
import ThreatLevelOrb from './ThreatLevelOrb';
import { THREAT_COLORS } from '../../services/live-soc/types';
import type { SOCRoomConfig, ThreatLevel, LobbyRoomStatus } from '../../services/live-soc/types';

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface RoomCardProps {
  room: SOCRoomConfig;
  status: LobbyRoomStatus;
  onEnter: (roomId: string) => void;
  onEdit: (room: SOCRoomConfig) => void;
  onDelete: (roomId: string) => void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GLASS =
  'bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl';

const THREAT_LABELS: Record<ThreatLevel, string> = {
  NOMINAL: 'NOMINAL',
  ELEVATED: 'ELEVATED',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatRps(rps: number): string {
  if (rps >= 1_000_000) return `~${(rps / 1_000_000).toFixed(1)}M`;
  if (rps >= 1_000) return `~${(rps / 1_000).toFixed(1)}K`;
  return `~${Math.round(rps)}`;
}

function formatTimeSince(isoString: string | null): string {
  if (!isoString) return 'Not started';
  const diffMs = Date.now() - new Date(isoString).getTime();
  const diffS = Math.floor(diffMs / 1000);
  if (diffS < 60) return `${diffS}s ago`;
  const diffM = Math.floor(diffS / 60);
  if (diffM < 60) return `${diffM}m ago`;
  return `${Math.floor(diffM / 60)}h ago`;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function RoomCard({
  room,
  status,
  onEnter,
  onEdit,
  onDelete,
}: RoomCardProps) {
  const [confirmDelete, setConfirmDelete] = useState(false);

  const threatColor = THREAT_COLORS[status.threatLevel];
  const isNominal = status.threatLevel === 'NOMINAL';

  // Pulse animation name derived from room id to avoid collisions
  const pulseAnim = useMemo(
    () => `card-pulse-${room.id.slice(0, 6)}`,
    [room.id],
  );

  const handleDelete = () => {
    if (confirmDelete) {
      onDelete(room.id);
    } else {
      setConfirmDelete(true);
      setTimeout(() => setConfirmDelete(false), 3000);
    }
  };

  return (
    <div
      className={`${GLASS} p-4 relative group transition-transform duration-200 hover:scale-[1.02] cursor-default`}
      style={
        !isNominal
          ? {
              borderColor: `${threatColor}44`,
              boxShadow: `0 0 20px ${threatColor}11, inset 0 0 30px ${threatColor}05`,
              animation: `${pulseAnim} 2s ease-in-out infinite`,
            }
          : undefined
      }
    >
      {/* Pulsing border keyframes for non-NOMINAL */}
      {!isNominal && (
        <style>{`
          @keyframes ${pulseAnim} {
            0%, 100% { border-color: ${threatColor}44; box-shadow: 0 0 20px ${threatColor}11, inset 0 0 30px ${threatColor}05; }
            50% { border-color: ${threatColor}88; box-shadow: 0 0 30px ${threatColor}22, inset 0 0 40px ${threatColor}0a; }
          }
        `}</style>
      )}

      {/* Top row: name + orb */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1 min-w-0 mr-3">
          <h3 className="text-sm font-semibold text-gray-100 truncate">
            {room.name}
          </h3>
          <div className="text-xs text-gray-500 font-mono mt-0.5 truncate">
            {room.namespace}
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <ThreatLevelOrb level={status.threatLevel} size="sm" />
          <span
            className="text-xs font-bold tracking-wider"
            style={{ color: threatColor }}
          >
            {THREAT_LABELS[status.threatLevel]}
          </span>
        </div>
      </div>

      {/* Metrics row */}
      <div className="grid grid-cols-4 gap-3 mb-3">
        {/* RPS */}
        <div className="text-center">
          <div className="text-xs text-gray-500 mb-0.5 flex items-center justify-center gap-1">
            <Activity size={10} />
            RPS
          </div>
          <div className="text-sm font-mono font-semibold text-[#00d4ff]">
            {formatRps(status.rps)}
          </div>
        </div>

        {/* Error Rate */}
        <div className="text-center">
          <div className="text-xs text-gray-500 mb-0.5 flex items-center justify-center gap-1">
            <AlertTriangle size={10} />
            Errors
          </div>
          <div
            className={`text-sm font-mono font-semibold ${
              status.errorRate > 5
                ? 'text-[#ff0040]'
                : status.errorRate > 1
                ? 'text-[#ffbe0b]'
                : 'text-[#00ff88]'
            }`}
          >
            {status.errorRate.toFixed(1)}%
          </div>
        </div>

        {/* Incidents */}
        <div className="text-center">
          <div className="text-xs text-gray-500 mb-0.5 flex items-center justify-center gap-1">
            <ShieldAlert size={10} />
            Incidents
          </div>
          <div
            className={`text-sm font-mono font-semibold ${
              status.incidentCount > 0 ? 'text-[#ff0040]' : 'text-gray-400'
            }`}
          >
            {status.incidentCount}
          </div>
        </div>

        {/* LB Count */}
        <div className="text-center">
          <div className="text-xs text-gray-500 mb-0.5 flex items-center justify-center gap-1">
            <Server size={10} />
            LBs
          </div>
          <div className="text-sm font-mono font-semibold text-gray-300">
            {room.loadBalancers.length}
          </div>
        </div>
      </div>

      {/* Last poll */}
      <div className="flex items-center gap-1.5 text-xs text-gray-500 mb-4">
        <Clock size={11} />
        <span>
          Last poll:{' '}
          <span
            className={
              status.isPolling ? 'text-[#00ff88]' : 'text-gray-400'
            }
          >
            {status.isPolling
              ? formatTimeSince(status.lastPollTimestamp)
              : 'Not started'}
          </span>
        </span>
        {status.isPolling && (
          <span className="ml-auto flex items-center gap-1 text-[#00ff88]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#00ff88] animate-pulse" />
            Live
          </span>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2">
        {/* Enter button */}
        <button
          type="button"
          onClick={() => onEnter(room.id)}
          className="flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/30 hover:bg-[#00d4ff]/20 transition-colors"
        >
          <LogIn size={14} />
          Enter
        </button>

        {/* Edit button */}
        <button
          type="button"
          onClick={() => onEdit(room)}
          className="p-2 rounded-lg text-gray-500 hover:text-[#00d4ff] hover:bg-[#00d4ff]/10 border border-[#1a2332] transition-colors"
          title="Edit room"
        >
          <Pencil size={14} />
        </button>

        {/* Delete button */}
        <button
          type="button"
          onClick={handleDelete}
          className={`p-2 rounded-lg border transition-colors ${
            confirmDelete
              ? 'text-[#ff0040] bg-[#ff0040]/10 border-[#ff0040]/30'
              : 'text-gray-500 hover:text-[#ff0040] hover:bg-[#ff0040]/10 border-[#1a2332]'
          }`}
          title={confirmDelete ? 'Click again to confirm' : 'Delete room'}
        >
          <Trash2 size={14} />
        </button>

        {/* Confirmation label */}
        {confirmDelete && (
          <span className="text-[10px] text-[#ff0040] animate-pulse">
            Confirm?
          </span>
        )}
      </div>
    </div>
  );
}
