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

  // --- NEW: AC1 + AC2 lock ---
  // Worked example: full-word primary grid, letters demoted as labelled secondary reference.
  // RED until impl adds data-testid="cvss-raw-vector" and "Raw vector" caption (AC2).
  it('AC1+AC2: renders full-word metric names/values as primary and demotes raw vector as a labelled secondary reference', () => {
    render(<CvssVectorBreakdown vector={VALID_VECTOR} />);

    // AC1: full-word metric names present in primary grid
    expect(screen.getByText('Attack Vector')).toBeInTheDocument();
    expect(screen.getByText('Attack Complexity')).toBeInTheDocument();
    expect(screen.getByText('Privileges Required')).toBeInTheDocument();
    expect(screen.getByText('User Interaction')).toBeInTheDocument();
    expect(screen.getByText('Scope')).toBeInTheDocument();
    expect(screen.getByText('Confidentiality')).toBeInTheDocument();
    expect(screen.getByText('Integrity')).toBeInTheDocument();
    expect(screen.getByText('Availability')).toBeInTheDocument();

    // AC1: full-word values present — VALID_VECTOR is AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
    expect(screen.getByText('Network')).toBeInTheDocument();   // AV=N → Network
    expect(screen.getByText('Low')).toBeInTheDocument();       // AC=L → Low
    expect(screen.getByText('Unchanged')).toBeInTheDocument(); // S=U → Unchanged
    // Availability=H → High; getAllByText because None appears for PR/UI/C/I
    expect(screen.getAllByText('High').length).toBeGreaterThanOrEqual(1);

    // AC1: no bare single-letter token is rendered as a standalone primary value.
    // The letters N, L, U, H only appear embedded inside the raw vector string;
    // an exact-text match must return null (no element whose sole text is that letter).
    expect(screen.queryByText('N')).toBeNull();
    expect(screen.queryByText('L')).toBeNull();
    expect(screen.queryByText('U')).toBeNull();
    // 'R' and 'C' do not appear in this vector's values, but guard anyway
    expect(screen.queryByText('R')).toBeNull();
    // Exact 'H' must be null — the only "High" occurrences are the full word
    expect(screen.queryByText('H')).toBeNull();

    // AC2: raw vector is present but as a clearly-secondary reference.
    // These assertions are RED until the implementer adds data-testid="cvss-raw-vector"
    // and a "Raw vector" caption label.
    const rawEl = screen.getByTestId('cvss-raw-vector');
    expect(rawEl).toBeInTheDocument();
    expect(rawEl).toHaveTextContent(/CVSS:3\.1\//);
    // A muted "Raw vector" caption must be rendered alongside the raw string
    expect(screen.getByText(/Raw vector/i)).toBeInTheDocument();
  });

  // --- NEW: AC1 lock — all-High vector ---
  // Ensures full-word values for PR/UI/Scope/C/I/A, no bare letters as primary values.
  it('AC1: all-High-ish vector renders PR/UI/Scope as full words, not bare letters', () => {
    const ALL_HIGH = 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H';
    render(<CvssVectorBreakdown vector={ALL_HIGH} />);

    // Full-word metric names
    expect(screen.getByText('Attack Complexity')).toBeInTheDocument();
    expect(screen.getByText('Privileges Required')).toBeInTheDocument();
    expect(screen.getByText('User Interaction')).toBeInTheDocument();
    expect(screen.getByText('Scope')).toBeInTheDocument();

    // Full-word values — not bare letters
    expect(screen.getByText('Required')).toBeInTheDocument();   // UI=R → Required (not 'R')
    expect(screen.getByText('Changed')).toBeInTheDocument();    // S=C → Changed (not 'C')
    // High appears for AC, PR, C, I, A — at least 4 times
    expect(screen.getAllByText('High').length).toBeGreaterThanOrEqual(4);

    // No bare single-letter primary values
    expect(screen.queryByText('H')).toBeNull();
    expect(screen.queryByText('R')).toBeNull();
    // 'C' as standalone: Scope=Changed so 'C' the letter must not appear as a primary value
    expect(screen.queryByText('C')).toBeNull();
  });

  // --- NEW: AC3 lock — graceful degradation for malformed and absent vectors ---
  it('AC3: malformed vector renders raw fallback without crash and no metric labels', () => {
    expect(() => render(<CvssVectorBreakdown vector="garbage" />)).not.toThrow();
    expect(screen.getByText('garbage')).toBeInTheDocument();
    expect(screen.queryByText('Attack Vector')).toBeNull();
  });

  it('AC3: null vector renders em-dash without crash', () => {
    expect(() => render(<CvssVectorBreakdown vector={null} />)).not.toThrow();
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('AC3: empty string vector renders em-dash without crash', () => {
    expect(() => render(<CvssVectorBreakdown vector="" />)).not.toThrow();
    expect(screen.getByText('—')).toBeInTheDocument();
  });
});
