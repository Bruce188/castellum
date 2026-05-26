import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { UserManagementPanel } from '../components/UserManagementPanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    listUsers: vi.fn(),
    createUser: vi.fn(),
    changeUserRole: vi.fn(),
    disableUser: vi.fn(),
  },
}));

const listUsers = vi.mocked(api.listUsers);
const createUser = vi.mocked(api.createUser);
const changeUserRole = vi.mocked(api.changeUserRole);
const disableUser = vi.mocked(api.disableUser);

beforeEach(() => {
  listUsers.mockReset();
  createUser.mockReset();
  changeUserRole.mockReset();
  disableUser.mockReset();
  vi.spyOn(window, 'confirm').mockReturnValue(true);
});

describe('<UserManagementPanel />', () => {
  it('renders the ADMIN-required notice for VIEWER and does not fetch users', () => {
    render(<UserManagementPanel isAdmin={false} />);
    expect(screen.getByText(/ADMIN role required/i)).toBeInTheDocument();
    expect(listUsers).not.toHaveBeenCalled();
  });

  it('ADMIN sees the user table populated from listUsers()', async () => {
    listUsers.mockResolvedValueOnce({
      content: [
        { id: 1, username: 'alice', role: 'ADMIN', enabled: true, createdAt: '2026-05-26T00:00:00Z', lastLoginAt: null },
        { id: 2, username: 'bob', role: 'VIEWER', enabled: true, createdAt: '2026-05-26T00:00:00Z', lastLoginAt: null },
      ],
      totalElements: 2,
      totalPages: 1,
      number: 0,
      size: 25,
    });

    render(<UserManagementPanel isAdmin={true} />);

    await waitFor(() => {
      expect(screen.getByTestId('user-row-alice')).toBeInTheDocument();
      expect(screen.getByTestId('user-row-bob')).toBeInTheDocument();
    });
  });

  it('submits the create-user form and reloads', async () => {
    listUsers
      .mockResolvedValueOnce({
        content: [],
        totalElements: 0, totalPages: 1, number: 0, size: 25,
      })
      .mockResolvedValueOnce({
        content: [
          { id: 5, username: 'carol', role: 'VIEWER', enabled: true, createdAt: null, lastLoginAt: null },
        ],
        totalElements: 1, totalPages: 1, number: 0, size: 25,
      });
    createUser.mockResolvedValueOnce({
      id: 5, username: 'carol', role: 'VIEWER', enabled: true, createdAt: null, lastLoginAt: null,
    });

    render(<UserManagementPanel isAdmin={true} />);
    await waitFor(() => expect(listUsers).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByTestId('new-username-input'), { target: { value: 'carol' } });
    fireEvent.change(screen.getByTestId('new-role-select'), { target: { value: 'VIEWER' } });
    fireEvent.change(screen.getByTestId('new-password-input'), { target: { value: 'newpassword1!' } });
    fireEvent.click(screen.getByRole('button', { name: /Create user/i }));

    await waitFor(() => {
      expect(createUser).toHaveBeenCalledWith({
        username: 'carol', role: 'VIEWER', initialPassword: 'newpassword1!',
      });
      expect(listUsers).toHaveBeenCalledTimes(2);
    });
  });

  it('role-change dropdown invokes api.changeUserRole', async () => {
    listUsers.mockResolvedValue({
      content: [
        { id: 1, username: 'alice', role: 'VIEWER', enabled: true, createdAt: null, lastLoginAt: null },
      ],
      totalElements: 1, totalPages: 1, number: 0, size: 25,
    });
    changeUserRole.mockResolvedValueOnce({
      id: 1, username: 'alice', role: 'ADMIN', enabled: true, createdAt: null, lastLoginAt: null,
    });

    render(<UserManagementPanel isAdmin={true} />);
    await waitFor(() => expect(screen.getByTestId('role-select-alice')).toBeInTheDocument());

    fireEvent.change(screen.getByTestId('role-select-alice'), { target: { value: 'ADMIN' } });

    await waitFor(() => {
      expect(changeUserRole).toHaveBeenCalledWith('alice', 'ADMIN');
    });
  });

  it('disable button calls api.disableUser after confirm', async () => {
    listUsers.mockResolvedValue({
      content: [
        { id: 1, username: 'alice', role: 'VIEWER', enabled: true, createdAt: null, lastLoginAt: null },
      ],
      totalElements: 1, totalPages: 1, number: 0, size: 25,
    });
    disableUser.mockResolvedValueOnce(undefined);

    render(<UserManagementPanel isAdmin={true} />);
    await waitFor(() => expect(screen.getByTestId('disable-btn-alice')).toBeInTheDocument());

    fireEvent.click(screen.getByTestId('disable-btn-alice'));

    await waitFor(() => {
      expect(disableUser).toHaveBeenCalledWith('alice');
    });
  });
});
