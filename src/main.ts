import './style.css';
import { renderHonestPanel } from './ui/honestPanel.js';
import { renderWorkbench } from './ui/workbench.js';
import { renderBudgetPanel } from './ui/budgetPanel.js';
import { renderUniquePanel } from './ui/uniquePanel.js';

type PanelKey = 'honest' | 'swap' | 'iv' | 'bias' | 'budget' | 'unique';

const renderers: Record<PanelKey, (root: HTMLElement) => void> = {
  honest: renderHonestPanel,
  swap: (root) => renderWorkbench(root, 'swap'),
  iv: (root) => renderWorkbench(root, 'iv'),
  bias: (root) => renderWorkbench(root, 'bias'),
  budget: renderBudgetPanel,
  unique: renderUniquePanel,
};

const rendered = new Set<PanelKey>();

function panelEl(key: PanelKey): HTMLElement {
  return document.getElementById(`panel-${key}`) as HTMLElement;
}

/** Panels render lazily, on first activation: a tab never clicked is a panel never in the DOM. */
function ensureRendered(key: PanelKey): void {
  if (rendered.has(key)) return;
  renderers[key](panelEl(key));
  rendered.add(key);
}

function selectTab(key: PanelKey): void {
  const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'));
  for (const tab of tabs) {
    const isActive = tab.dataset.panel === key;
    tab.setAttribute('aria-selected', String(isActive));
    tab.tabIndex = isActive ? 0 : -1;
    tab.classList.toggle('active', isActive);
    panelEl(tab.dataset.panel as PanelKey).hidden = !isActive;
  }
  ensureRendered(key);
}

function wireTabs(): void {
  const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'));
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => selectTab(tab.dataset.panel as PanelKey));
    // Roving-tabindex arrow-key navigation across the tablist (WAI-ARIA pattern).
    tab.addEventListener('keydown', (e) => {
      let next = -1;
      if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabs.length - 1;
      if (next >= 0) {
        e.preventDefault();
        tabs[next]!.focus();
        selectTab(tabs[next]!.dataset.panel as PanelKey);
      }
    });
  });
}

wireTabs();
selectTab('honest');
