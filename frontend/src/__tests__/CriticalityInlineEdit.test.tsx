import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { CriticalityInlineEdit } from '../components/CriticalityInlineEdit';

describe('<CriticalityInlineEdit />', () => {
  it('renders read-only text for VIEWER (isAdmin=false)', () => {
    render(<CriticalityInlineEdit value="HIGH" isAdmin={false} onSave={vi.fn()} />);
    expect(screen.getByTestId('criticality-readonly')).toHaveTextContent('HIGH');
    expect(screen.queryByRole('button', { name: /edit criticality/i })).not.toBeInTheDocument();
  });

  it('ADMIN sees an edit button that swaps to a dropdown', () => {
    render(<CriticalityInlineEdit value="MEDIUM" isAdmin={true} onSave={vi.fn()} />);
    const btn = screen.getByRole('button', { name: /edit criticality/i });
    fireEvent.click(btn);
    expect(screen.getByRole('combobox', { name: /criticality/i })).toBeInTheDocument();
  });

  it('selecting a different value calls onSave with that value', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(<CriticalityInlineEdit value="LOW" isAdmin={true} onSave={onSave} />);
    fireEvent.click(screen.getByRole('button', { name: /edit criticality/i }));
    fireEvent.change(screen.getByRole('combobox', { name: /criticality/i }), { target: { value: 'CRITICAL' } });
    await waitFor(() => expect(onSave).toHaveBeenCalledWith('CRITICAL'));
  });

  it('shows an inline error when save fails and leaves the dropdown open', async () => {
    const onSave = vi.fn().mockRejectedValue(new Error('boom'));
    render(<CriticalityInlineEdit value="LOW" isAdmin={true} onSave={onSave} />);
    fireEvent.click(screen.getByRole('button', { name: /edit criticality/i }));
    fireEvent.change(screen.getByRole('combobox', { name: /criticality/i }), { target: { value: 'HIGH' } });
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('boom'));
    // Dropdown still mounted (still editing).
    expect(screen.getByRole('combobox', { name: /criticality/i })).toBeInTheDocument();
  });

  it('selecting the current value just collapses without calling onSave', () => {
    const onSave = vi.fn();
    render(<CriticalityInlineEdit value="HIGH" isAdmin={true} onSave={onSave} />);
    fireEvent.click(screen.getByRole('button', { name: /edit criticality/i }));
    fireEvent.change(screen.getByRole('combobox', { name: /criticality/i }), { target: { value: 'HIGH' } });
    expect(onSave).not.toHaveBeenCalled();
  });

  it('ADMIN display mode renders the pencil-icon edit affordance', () => {
    render(<CriticalityInlineEdit value="MEDIUM" isAdmin={true} onSave={vi.fn()} />);
    const btn = screen.getByRole('button', { name: /edit criticality/i });
    expect(btn.querySelector('[data-testid="edit-affordance"]')).toBeInTheDocument();
  });

  it('VIEWER display mode does not render the edit affordance', () => {
    render(<CriticalityInlineEdit value="MEDIUM" isAdmin={false} onSave={vi.fn()} />);
    expect(screen.queryByTestId('edit-affordance')).not.toBeInTheDocument();
  });
});
