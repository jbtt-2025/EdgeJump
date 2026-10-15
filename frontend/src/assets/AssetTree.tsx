import React from 'react';
import { Folder, Server } from 'lucide-react';

type Group = { id: string; name: string; parentId: string | null };
type Asset = { id: string; name: string; groupIds?: string[]; groups?: Group[] };

export function groupPath(id: string, groups: Group[]): string {
  const names: string[] = []; const seen = new Set<string>();
  let group = groups.find((group) => group.id === id);
  while (group && !seen.has(group.id)) { seen.add(group.id); names.unshift(group.name); group = groups.find((parent) => parent.id === group!.parentId); }
  return names.join(' / ');
}

export function AssetTree({ groups, assets, onGroup, onAsset, selected }: {
  groups: Group[]; assets: Asset[]; onGroup: (id: string | null) => void; onAsset?: (id: string) => void; selected?: string | null;
}) {
  function branches(parentId: string | null, seen: Set<string> = new Set()): React.ReactNode {
    return groups.filter((group) => group.parentId === parentId || parentId === null && !groups.some((parent) => parent.id === group.parentId)).filter((group) => !seen.has(group.id)).map((group) => {
      const next = new Set(seen).add(group.id);
      return <li key={group.id} className="mt-2"><button onClick={() => onGroup(group.id)} className={`flex items-center gap-2 py-1 text-left ${selected === group.id ? 'text-blue-300' : 'text-slate-300'}`}><Folder size={15} className="shrink-0 text-blue-400" />{group.name}</button>
        <ul className="ml-2.5 pl-4 border-l border-slate-700">{branches(group.id, next)}{assets.filter((asset) => (asset.groupIds ?? asset.groups?.slice(0, 1).map((item) => item.id) ?? []).includes(group.id)).map((asset) => <li key={asset.id}><button onClick={() => onAsset?.(asset.id)} className="flex items-center gap-2 py-2 text-slate-400 text-left"><Server size={13} className="shrink-0" />{asset.name}</button></li>)}</ul>
      </li>;
    });
  }
  return <nav aria-label="资产树" className="text-sm"><button onClick={() => onGroup(null)} className="font-medium py-2 text-slate-200">全部资产</button><ul>{branches(null)}</ul></nav>;
}
