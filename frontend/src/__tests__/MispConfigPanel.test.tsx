import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MispConfigPanel } from '../components/MispConfigPanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    getIntegrationConfig: vi.fn(),
    saveIntegrationConfig: vi.fn(),
    pushIntegration: vi.fn(),
  },
}));

const getIntegrationConfig = vi.mocked(api.getIntegrationConfig);
const saveIntegrationConfig = vi.mocked(api.saveIntegrationConfig);
const pushIntegration = vi.mocked(api.pushIntegration);

beforeEach(() => {
  getIntegrationConfig.mockReset();
  saveIntegrationConfig.mockReset();
  pushIntegration.mockReset();
});

describe('<MispConfigPanel />', () => {
  it('VIEWER sees the ADMIN-required notice and never calls the backend', () => {
    render(<MispConfigPanel isAdmin={false} />);
    expect(screen.getByText(/ADMIN role required/i)).toBeInTheDocument();
    expect(getIntegrationConfig).not.toHaveBeenCalled();
  });

  it('save submits config + api key', async () => {
    getIntegrationConfig.mockRejectedValueOnce(new Error('404 Not Found'));
    saveIntegrationConfig.mockResolvedValueOnce({
      id: 5, integrationType: 'MISP',
      config: { url: 'https://misp.example' },
      credentialsSet: true, lastPushAt: null, lastPushStatus: null,
      createdAt: '2026-05-26T00:00:00Z', updatedAt: '2026-05-26T00:00:00Z',
    });

    render(<MispConfigPanel isAdmin={true} />);
    await waitFor(() => expect(getIntegrationConfig).toHaveBeenCalled());

    fireEvent.change(screen.getByTestId('misp-url-input'), { target: { value: 'https://misp.example' } });
    fireEvent.change(screen.getByTestId('misp-api-key-input'), { target: { value: 'misp-key-XYZ' } });
    fireEvent.click(screen.getByTestId('misp-save-btn'));

    await waitFor(() => expect(saveIntegrationConfig).toHaveBeenCalled());
    const [, payload] = saveIntegrationConfig.mock.calls[0];
    expect(payload.credentials).toBe('misp-key-XYZ');
    expect((payload.config as Record<string, string>).url).toBe('https://misp.example');
    await waitFor(() => expect(screen.getByTestId('misp-msg')).toHaveTextContent(/saved/i));
  });

  it('push button disabled until config complete; tooltip explains why', async () => {
    getIntegrationConfig.mockRejectedValueOnce(new Error('404 Not Found'));
    render(<MispConfigPanel isAdmin={true} />);
    await waitFor(() => expect(getIntegrationConfig).toHaveBeenCalled());

    const pushBtn = screen.getByTestId('misp-push-btn') as HTMLButtonElement;
    expect(pushBtn.disabled).toBe(true);
    expect(pushBtn.title).toMatch(/Save a complete config/);

    fireEvent.change(screen.getByTestId('misp-url-input'), { target: { value: 'https://misp.example' } });
    fireEvent.change(screen.getByTestId('misp-api-key-input'), { target: { value: 'k' } });
    expect(pushBtn.disabled).toBe(false);
  });

  it('push triggers POST /api/integrations/MISP/push and updates last-push inline', async () => {
    getIntegrationConfig.mockResolvedValueOnce({
      id: 8, integrationType: 'MISP',
      config: { url: 'https://misp.example' },
      credentialsSet: true, lastPushAt: null, lastPushStatus: null,
      createdAt: '2026-05-26T00:00:00Z', updatedAt: '2026-05-26T00:00:00Z',
    });
    pushIntegration.mockResolvedValueOnce({
      status: 'ok',
      bundleId: 'bundle--m1',
      pushedAt: '2026-05-26T02:00:00Z',
      lastPushStatus: 'SUCCESS: event=evt-99',
    });

    render(<MispConfigPanel isAdmin={true} />);
    await waitFor(() => expect(screen.getByTestId('misp-push-btn')).not.toBeDisabled());

    fireEvent.click(screen.getByTestId('misp-push-btn'));

    await waitFor(() => expect(pushIntegration).toHaveBeenCalledWith('MISP'));
    await waitFor(() => {
      expect(screen.getByTestId('misp-last-push-status').textContent).toContain('evt-99');
      expect(screen.getByTestId('misp-last-push-at').textContent).toContain('2026-05-26T02:00:00Z');
    });
  });
});
