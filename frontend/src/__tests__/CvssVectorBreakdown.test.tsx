import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { CvssVectorBreakdown } from '../components/CvssVectorBreakdown';

const VALID_VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H';

describe('<CvssVectorBreakdown />', () => {
  it('renders the decoded metric grid for a valid vector', () => {
    render(<CvssVectorBreakdown vector={VALID_VECTOR} />);
    expect(screen.getByText('Attack Vector')).toBeInTheDocument();
    expect(screen.getByText('Network')).toBeInTheDocument();
    expect(screen.getByText('Availability')).toBeInTheDocument();
    // Availability is High in this fixture — at least one "High" must show.
    expect(screen.getAllByText('High').length).toBeGreaterThanOrEqual(1);
  });

  it('shows the raw vector string alongside the decode', () => {
    render(<CvssVectorBreakdown vector={VALID_VECTOR} />);
    expect(screen.getByText(/CVSS:3\.1\//)).toBeInTheDocument();
  });

  it('renders the severity band label when a score is supplied', () => {
    render(<CvssVectorBreakdown vector={VALID_VECTOR} score="7.8" />);
    // The band element carries data-testid="cvss-severity-band" (contract).
    const band = screen.getByTestId('cvss-severity-band');
    expect(band).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
  });

  it('renders no severity band element when no score is supplied', () => {
    render(<CvssVectorBreakdown vector={VALID_VECTOR} />);
    expect(screen.queryByTestId('cvss-severity-band')).toBeNull();
  });

  it('falls back to the raw string and shows no metric labels for a malformed vector', () => {
    render(<CvssVectorBreakdown vector="garbage" />);
    expect(screen.getByText('garbage')).toBeInTheDocument();
    expect(screen.queryByText('Attack Vector')).toBeNull();
  });

  it('renders an em-dash and does not crash for an absent vector', () => {
    expect(() => render(<CvssVectorBreakdown vector={null} />)).not.toThrow();
    expect(screen.getByText('—')).toBeInTheDocument();
  });
});
