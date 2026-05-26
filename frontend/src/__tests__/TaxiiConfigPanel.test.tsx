import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TaxiiConfigPanel } from '../components/TaxiiConfigPanel';
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

describe('<TaxiiConfigPanel />', () => {
  it('VIEWER sees the ADMIN-required notice and never calls the backend', () => {
    render(<TaxiiConfigPanel isAdmin={false} />);
    expect(screen.getByText(/ADMIN role required/i)).toBeInTheDocument();
    expect(getIntegrationConfig).not.toHaveBeenCalled();
  });

  it('ADMIN sees the saved config hydrated on mount', async () => {
    getIntegrationConfig.mockResolvedValueOnce({
      id: 1,
      integrationType: 'TAXII',
      config: { url: 'https://taxii.example', collectionId: 'cid-1', username: 'alice' },
      credentialsSet: true,
      lastPushAt: '2026-05-26T00:00:00Z',
      lastPushStatus: 'SUCCESS: status=202',
      createdAt: '2026-05-26T00:00:00Z',
      updatedAt: '2026-05-26T00:00:00Z',
    });

    render(<TaxiiConfigPanel isAdmin={true} />);

    await waitFor(() => {
      expect((screen.getByTestId('taxii-url-input') as HTMLInputElement).value)
        .toBe('https://taxii.example');
    });
    expect((screen.getByTestId('taxii-collection-input') as HTMLInputElement).value).toBe('cid-1');
    expect(screen.getByTestId('taxii-last-push-status').textContent).toContain('SUCCESS');
  });

  it('blank panel when no config saved yet (404 response)', async () => {
    getIntegrationConfig.mockRejectedValueOnce(new Error('404 Not Found'));
    render(<TaxiiConfigPanel isAdmin={true} />);
    await waitFor(() => expect(screen.getByText(/No TAXII config saved yet/i)).toBeInTheDocument());
  });

  it('save submits config + credentials and reloads', async () => {
    getIntegrationConfig.mockRejectedValueOnce(new Error('404 Not Found'));
    saveIntegrationConfig.mockResolvedValueOnce({
      id: 5, integrationType: 'TAXII',
      config: { url: 'https://t.example', collectionId: 'cid', apiRoot: '', username: '' },
      credentialsSet: true, lastPushAt: null, lastPushStatus: null,
      createdAt: '2026-05-26T00:00:00Z', updatedAt: '2026-05-26T00:00:00Z',
    });

    render(<TaxiiConfigPanel isAdmin={true} />);
    await waitFor(() => expect(getIntegrationConfig).toHaveBeenCalled());

    fireEvent.change(screen.getByTestId('taxii-url-input'), { target: { value: 'https://t.example' } });
    fireEvent.change(screen.getByTestId('taxii-collection-input'), { target: { value: 'cid' } });
    fireEvent.change(screen.getByTestId('taxii-password-input'), { target: { value: 'pwd-secret' } });
    fireEvent.click(screen.getByTestId('taxii-save-btn'));

    await waitFor(() => expect(saveIntegrationConfig).toHaveBeenCalled());
    const [, payload] = saveIntegrationConfig.mock.calls[0];
    expect(payload.credentials).toBe('pwd-secret');
    expect((payload.config as Record<string, string>).url).toBe('https://t.example');
    expect((payload.config as Record<string, string>).collectionId).toBe('cid');
    await waitFor(() => expect(screen.getByTestId('taxii-msg')).toHaveTextContent(/saved/i));
  });

  it('push button is disabled when config is incomplete and enabled when complete', async () => {
    getIntegrationConfig.mockRejectedValueOnce(new Error('404 Not Found'));
    render(<TaxiiConfigPanel isAdmin={true} />);
    await waitFor(() => expect(getIntegrationConfig).toHaveBeenCalled());

    const pushBtn = screen.getByTestId('taxii-push-btn') as HTMLButtonElement;
    expect(pushBtn.disabled).toBe(true);
    expect(pushBtn.title).toMatch(/Save a complete config/);

    fireEvent.change(screen.getByTestId('taxii-url-input'), { target: { value: 'https://t.example' } });
    fireEvent.change(screen.getByTestId('taxii-collection-input'), { target: { value: 'cid' } });
    fireEvent.change(screen.getByTestId('taxii-password-input'), { target: { value: 'pwd-secret' } });
    expect(pushBtn.disabled).toBe(false);
  });

  it('push surfaces last-push status inline on success', async () => {
    getIntegrationConfig.mockResolvedValueOnce({
      id: 1, integrationType: 'TAXII',
      config: { url: 'https://t.example', collectionId: 'cid' },
      credentialsSet: true, lastPushAt: null, lastPushStatus: null,
      createdAt: '2026-05-26T00:00:00Z', updatedAt: '2026-05-26T00:00:00Z',
    });
    pushIntegration.mockResolvedValueOnce({
      status: 'ok',
      bundleId: 'bundle--xyz',
      pushedAt: '2026-05-26T01:23:45Z',
      lastPushStatus: 'SUCCESS: status=202',
    });

    render(<TaxiiConfigPanel isAdmin={true} />);
    await waitFor(() => expect(screen.getByTestId('taxii-push-btn')).not.toBeDisabled());

    fireEvent.click(screen.getByTestId('taxii-push-btn'));

    await waitFor(() => expect(pushIntegration).toHaveBeenCalledWith('TAXII'));
    await waitFor(() => {
      expect(screen.getByTestId('taxii-last-push-status').textContent).toContain('SUCCESS');
      expect(screen.getByTestId('taxii-last-push-at').textContent).toContain('2026-05-26T01:23:45Z');
    });
  });

  it('push surfaces last-push status inline on error', async () => {
    getIntegrationConfig.mockResolvedValueOnce({
      id: 1, integrationType: 'TAXII',
      config: { url: 'https://t.example', collectionId: 'cid' },
      credentialsSet: true, lastPushAt: null, lastPushStatus: null,
      createdAt: '2026-05-26T00:00:00Z', updatedAt: '2026-05-26T00:00:00Z',
    });
    pushIntegration.mockResolvedValueOnce({
      status: 'error',
      bundleId: null,
      pushedAt: '2026-05-26T01:23:45Z',
      lastPushStatus: 'ERROR: connection refused',
    });

    render(<TaxiiConfigPanel isAdmin={true} />);
    await waitFor(() => expect(screen.getByTestId('taxii-push-btn')).not.toBeDisabled());

    fireEvent.click(screen.getByTestId('taxii-push-btn'));

    await waitFor(() => {
      expect(screen.getByTestId('taxii-last-push-status').textContent).toContain('connection refused');
    });
  });
});
