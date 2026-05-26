import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ForcePasswordRotation } from '../components/ForcePasswordRotation';
import { api } from '../api/client';
import * as useAuthMod from '../hooks/useAuth';

vi.mock('../api/client', () => ({
  api: {
    changePassword: vi.fn(),
  },
}));

const changePassword = vi.mocked(api.changePassword);

beforeEach(() => {
  changePassword.mockReset();
});

describe('<ForcePasswordRotation />', () => {
  it('renders the dialog with the form and a bootstrap warning', () => {
    render(<ForcePasswordRotation />);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByTestId('change-password-form')).toBeInTheDocument();
    expect(screen.getByText(/bootstrap account/i)).toBeInTheDocument();
  });

  it('on submit success: clears the must-change flag', async () => {
    changePassword.mockResolvedValueOnce(undefined);
    const clearSpy = vi.spyOn(useAuthMod, 'clearMustChangePassword').mockImplementation(() => {});

    render(<ForcePasswordRotation />);

    fireEvent.change(screen.getByTestId('old-password-input'), { target: { value: 'bootstrap-pw' } });
    fireEvent.change(screen.getByTestId('new-password-input'), { target: { value: 'newpassword1!' } });
    fireEvent.change(screen.getByTestId('confirm-password-input'), { target: { value: 'newpassword1!' } });
    fireEvent.click(screen.getByRole('button', { name: /Change password/i }));

    await waitFor(() => expect(changePassword).toHaveBeenCalled());
    expect(clearSpy).toHaveBeenCalled();
  });
});
