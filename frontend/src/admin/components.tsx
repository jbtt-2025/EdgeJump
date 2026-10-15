import React from 'react';

export const inputClass = 'w-full bg-slate-950 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-400';
export const buttonClass = 'px-3 py-2 text-sm rounded-lg bg-slate-700 hover:bg-slate-600 disabled:opacity-50';
export const primaryClass = 'px-4 py-2 text-sm rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50';

export function Field({ label, children }: { label: string; children: React.ReactNode }) { return <label className="block space-y-2 text-sm text-slate-300"><span>{label}</span>{children}</label>; }
export function Choices({ label, options, value, onChange }: { label: string; options: { id: string; label: string }[]; value: string[]; onChange: (values: string[]) => void }) {
  return <fieldset className="border border-slate-700 rounded-lg p-3"><legend className="px-1 text-sm text-slate-300">{label}</legend><div className="max-h-40 overflow-y-auto space-y-2">{options.map((option) => <label key={option.id} className="flex gap-2 items-start text-sm"><input type="checkbox" className="mt-1" checked={value.includes(option.id)} onChange={(event) => onChange(event.target.checked ? [...value, option.id] : value.filter((id) => id !== option.id))} /><span>{option.label}</span></label>)}{!options.length && <p className="text-slate-500 text-sm">暂无可选项</p>}</div></fieldset>;
}
export function Table({ columns, children, empty }: { columns: string[]; children: React.ReactNode; empty?: boolean }) { return <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-slate-400 bg-slate-950/40"><tr>{columns.map((column) => <th key={column} className="p-3 font-medium whitespace-nowrap">{column}</th>)}</tr></thead><tbody className="divide-y divide-slate-700">{children}</tbody></table>{empty && <p className="p-12 text-center text-slate-400">暂无记录</p>}</div>; }
export const Cell = ({ children }: { children?: React.ReactNode }) => <td className="p-3 align-top">{children}</td>;

