import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { OnboardingCard } from '../components/OnboardingCard';

describe('<OnboardingCard />', () => {
  it('renders all three onboarding steps when scanCount is zero', () => {
    render(<OnboardingCard scanCount={0} />);
    expect(screen.getByTestId('onboarding-card')).toBeInTheDocument();
    expect(screen.getByText(/Sync threat-intel feeds/i)).toBeInTheDocument();
    expect(screen.getByText(/Run a scan/i)).toBeInTheDocument();
    expect(screen.getByText(/Set device criticality/i)).toBeInTheDocument();
    // Steps 1/2/3 markers
    expect(screen.getByText('1')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
  });

  it('renders nothing once at least one scan exists', () => {
    const { container } = render(<OnboardingCard scanCount={1} />);
    expect(container.firstChild).toBeNull();
  });

  it('renders nothing for arbitrarily large scan counts', () => {
    const { container } = render(<OnboardingCard scanCount={42} />);
    expect(container.firstChild).toBeNull();
  });
});
