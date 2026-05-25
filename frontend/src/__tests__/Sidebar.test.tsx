import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { Sidebar } from '../components/Sidebar';

describe('<Sidebar />', () => {
  it('renders all six top-level nav items', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <Sidebar />
      </MemoryRouter>
    );
    expect(screen.getByRole('link', { name: 'Topology' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Scans' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Threats' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'CVEs' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Audit' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Settings' })).toBeInTheDocument();
  });

  it('marks Topology link active when on "/"', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <Sidebar />
      </MemoryRouter>
    );
    const topology = screen.getByRole('link', { name: 'Topology' });
    expect(topology.className).toMatch(/bg-slate-700/);
  });

  it('marks Threats link active when on "/threats"', () => {
    render(
      <MemoryRouter initialEntries={['/threats']}>
        <Sidebar />
      </MemoryRouter>
    );
    const threats = screen.getByRole('link', { name: 'Threats' });
    expect(threats.className).toMatch(/bg-slate-700/);
    const topology = screen.getByRole('link', { name: 'Topology' });
    expect(topology.className).not.toMatch(/bg-slate-700/);
  });

  it('uses "end" matching so Topology is NOT marked active on "/scans"', () => {
    render(
      <MemoryRouter initialEntries={['/scans']}>
        <Sidebar />
      </MemoryRouter>
    );
    const topology = screen.getByRole('link', { name: 'Topology' });
    expect(topology.className).not.toMatch(/bg-slate-700/);
  });
});
