import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { HostnameInlineEdit } from '../components/HostnameInlineEdit';

describe('<HostnameInlineEdit />', () => {
  it('renders read-only for VIEWER (isAdmin=false)', () => {
    render(<HostnameInlineEdit value="webhost-01" isAdmin={false} onSave={vi.fn()} />);
    expect(screen.getByTestId('hostname-readonly')).toHaveTextContent('webhost-01');
    expect(screen.queryByRole('button', { name: /edit hostname/i })).not.toBeInTheDocument();
  });

  it('renders em-dash for null hostname in read-only mode', () => {
    render(<HostnameInlineEdit value={null} isAdmin={false} onSave={vi.fn()} />);
    expect(screen.getByTestId('hostname-readonly')).toHaveTextContent('—');
  });

  it('ADMIN click opens an input pre-filled with the current value', () => {
    render(<HostnameInlineEdit value="webhost-01" isAdmin={true} onSave={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: /edit hostname/i }));
    const input = screen.getByRole('textbox', { name: /hostname/i }) as HTMLInputElement;
    expect(input.value).toBe('webhost-01');
  });

  it('Enter commits trimmed value via onSave', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(<HostnameInlineEdit value="webhost-01" isAdmin={true} onSave={onSave} />);
    fireEvent.click(screen.getByRole('button', { name: /edit hostname/i }));
    const input = screen.getByRole('textbox', { name: /hostname/i });
    fireEvent.change(input, { target: { value: '  renamed  ' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    await waitFor(() => expect(onSave).toHaveBeenCalledWith('renamed'));
  });

  it('Escape cancels without calling onSave', () => {
    const onSave = vi.fn();
    render(<HostnameInlineEdit value="webhost-01" isAdmin={true} onSave={onSave} />);
    fireEvent.click(screen.getByRole('button', { name: /edit hostname/i }));
    const input = screen.getByRole('textbox', { name: /hostname/i });
    fireEvent.change(input, { target: { value: 'changed' } });
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(onSave).not.toHaveBeenCalled();
    // The display button is back.
    expect(screen.getByRole('button', { name: /edit hostname/i })).toBeInTheDocument();
  });

  it('rejects empty hostname with inline error', () => {
    const onSave = vi.fn();
    render(<HostnameInlineEdit value="webhost-01" isAdmin={true} onSave={onSave} />);
    fireEvent.click(screen.getByRole('button', { name: /edit hostname/i }));
    const input = screen.getByRole('textbox', { name: /hostname/i });
    fireEvent.change(input, { target: { value: '   ' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent(/empty/i);
  });

  it('shows error and stays editing when save fails', async () => {
    const onSave = vi.fn().mockRejectedValue(new Error('save-failed'));
    render(<HostnameInlineEdit value="webhost-01" isAdmin={true} onSave={onSave} />);
    fireEvent.click(screen.getByRole('button', { name: /edit hostname/i }));
    const input = screen.getByRole('textbox', { name: /hostname/i });
    fireEvent.change(input, { target: { value: 'new-name' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('save-failed'));
  });
});
