import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { RiskTierKey } from '../components/RiskTierKey';
import { tierColor } from '../lib/riskTier';

describe('<RiskTierKey />', () => {
  it('riskTierKey_rendersFiveSwatchesSourcedFromTierColor', () => {
    render(<RiskTierKey />);
    const tiers = ['low', 'med', 'high', 'crit', 'unknown'] as const;
    for (const t of tiers) {
      const el = screen.getByTestId(`tier-swatch-${t}`);
      expect(el).toBeInTheDocument();
      expect(el).toHaveStyle({ backgroundColor: tierColor[t] });
    }
  });

  it('riskTierKey_rendersAccessibleTierLabels', () => {
    render(<RiskTierKey />);
    expect(screen.getByText(/^Low$/)).toBeInTheDocument();
    expect(screen.getByText(/^Medium$/)).toBeInTheDocument();
    expect(screen.getByText(/^High$/)).toBeInTheDocument();
    expect(screen.getByText(/^Critical$/)).toBeInTheDocument();
    expect(screen.getByText(/^Unknown$/)).toBeInTheDocument();
  });

  it('riskTierKey_isNonInteractive', () => {
    render(<RiskTierKey />);
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0);
    expect(screen.queryAllByRole('button')).toHaveLength(0);
  });
});
