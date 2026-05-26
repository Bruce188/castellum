import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ChangePasswordForm } from '../components/ChangePasswordForm';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    changePassword: vi.fn(),
  },
}));

const changePassword = vi.mocked(api.changePassword);

beforeEach(() => {
  changePassword.mockReset();
});

describe('<ChangePasswordForm />', () => {
  it('submits oldPassword + newPassword on happy path; calls onSuccess', async () => {
    changePassword.mockResolvedValueOnce(undefined);
    const onSuccess = vi.fn();
    render(<ChangePasswordForm onSuccess={onSuccess} />);

    fireEvent.change(screen.getByTestId('old-password-input'), { target: { value: 'old-pw' } });
    fireEvent.change(screen.getByTestId('new-password-input'), { target: { value: 'newpassword1!' } });
    fireEvent.change(screen.getByTestId('confirm-password-input'), { target: { value: 'newpassword1!' } });
    fireEvent.click(screen.getByRole('button', { name: /Change password/i }));

    await waitFor(() => expect(changePassword).toHaveBeenCalledTimes(1));
    expect(changePassword).toHaveBeenCalledWith({
      oldPassword: 'old-pw',
      newPassword: 'newpassword1!',
    });
    expect(onSuccess).toHaveBeenCalled();
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent(/Password changed/i);
    });
  });

  it('rejects mismatched confirm field without calling the API', async () => {
    render(<ChangePasswordForm />);
    fireEvent.change(screen.getByTestId('old-password-input'), { target: { value: 'old-pw' } });
    fireEvent.change(screen.getByTestId('new-password-input'), { target: { value: 'newpassword1!' } });
    fireEvent.change(screen.getByTestId('confirm-password-input'), { target: { value: 'differentpassword' } });
    fireEvent.click(screen.getByRole('button', { name: /Change password/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/do not match/i);
    });
    expect(changePassword).not.toHaveBeenCalled();
  });

  it('rejects too-short new password without calling the API', async () => {
    render(<ChangePasswordForm />);
    fireEvent.change(screen.getByTestId('old-password-input'), { target: { value: 'old-pw' } });
    // Mirror the minLength relaxation pattern other tests use — drive the input
    // event directly so the browser-side `minLength` check doesn't block submit.
    fireEvent.change(screen.getByTestId('new-password-input'), { target: { value: 'shorty' } });
    fireEvent.change(screen.getByTestId('confirm-password-input'), { target: { value: 'shorty' } });
    const button = screen.getByRole('button', { name: /Change password/i });
    // The disabled-state guard alone is also acceptable; force-submit to assert
    // the form-level message even if a future style removes the disabled attr.
    fireEvent.submit(button.closest('form')!);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/at least 8 characters/i);
    });
    expect(changePassword).not.toHaveBeenCalled();
  });

  it('surfaces "Old password is incorrect" on 401 from server', async () => {
    changePassword.mockRejectedValueOnce(new Error('401 Old password incorrect'));
    render(<ChangePasswordForm />);
    fireEvent.change(screen.getByTestId('old-password-input'), { target: { value: 'wrong' } });
    fireEvent.change(screen.getByTestId('new-password-input'), { target: { value: 'newpassword1!' } });
    fireEvent.change(screen.getByTestId('confirm-password-input'), { target: { value: 'newpassword1!' } });
    fireEvent.click(screen.getByRole('button', { name: /Change password/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/incorrect/i);
    });
  });

  it('surfaces rate-limit message on 429', async () => {
    changePassword.mockRejectedValueOnce(new Error('429 Too Many Requests — retry after 45s'));
    render(<ChangePasswordForm />);
    fireEvent.change(screen.getByTestId('old-password-input'), { target: { value: 'old-pw' } });
    fireEvent.change(screen.getByTestId('new-password-input'), { target: { value: 'newpassword1!' } });
    fireEvent.change(screen.getByTestId('confirm-password-input'), { target: { value: 'newpassword1!' } });
    fireEvent.click(screen.getByRole('button', { name: /Change password/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/retry after 45s/i);
    });
  });
});
