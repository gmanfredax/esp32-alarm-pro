/* script.js — Gestione wizard UI e helper generici */
(() => {
  const globalCfg = window.APP_CONFIG || {};
  const defaults = {
    enabled: true,
    autoShow: true,
    alwaysShow: false,
    storageKey: 'alarmpro_wizard_v1',
    fallbackDelayMs: 3500,
    reopenSelector: '[data-act="wizard"]',
    prevLabel: 'Indietro',
    nextLabel: 'Avanti',
    doneLabel: 'Vai alla dashboard',
    skipLabel: 'Mostra più tardi',
    steps: []
  };

  const wizardCfg = Object.assign({}, defaults, globalCfg.wizard || {});
  const rawSteps = Array.isArray(wizardCfg.steps) ? wizardCfg.steps : [];
  const steps = rawSteps
    .map(step => step && typeof step === 'object' ? step : null)
    .filter(Boolean);

  const storageKey = wizardCfg.storageKey || defaults.storageKey;
  const autoShowEnabled = wizardCfg.autoShow !== false;
  const showEvenIfSeen = wizardCfg.alwaysShow === true;

  function hasSeen() {
    try {
      return localStorage.getItem(storageKey) === '1';
    } catch (_) {
      return false;
    }
  }

  function markSeen() {
    try {
      localStorage.setItem(storageKey, '1');
    } catch (_) {}
  }

  function resetSeen() {
    try {
      localStorage.removeItem(storageKey);
      sessionStorage.removeItem(storageKey);
    } catch (_) {}
  }

  const api = window.ALARM_UI = Object.assign(window.ALARM_UI || {}, {
    openWizard: (startIndex = 0) => {
      const instance = ensureWizard();
      instance.show(startIndex);
    },
    resetWizard: () => {
      resetSeen();
      const instance = ensureWizard(true);
      instance.show(0);
    },
    hasSeenWizard: () => hasSeen()
  });

  if (!wizardCfg.enabled || steps.length === 0) {
    return;
  }

  let wizardInstance = null;

  function ensureWizard(forceRebuild = false) {
    if (!forceRebuild && wizardInstance) {
      return wizardInstance;
    }

    const overlay = document.createElement('div');
    overlay.className = 'setup-wizard hidden';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');

    const progressDots = steps.map(() => '<span></span>').join('');

    overlay.innerHTML = `
      <div class="wizard-card">
        <button class="wizard-close" type="button" aria-label="Chiudi">&times;</button>
        <div class="wizard-progress" role="tablist">${progressDots}</div>
        <div class="wizard-content">
          <div class="wizard-step-icon hidden" aria-hidden="true"></div>
          <h2 class="wizard-step-title"></h2>
          <div class="wizard-step-body"></div>
        </div>
        <div class="wizard-actions">
          <button class="wizard-skip" type="button">${wizardCfg.skipLabel || defaults.skipLabel}</button>
          <div class="wizard-actions-nav">
            <button class="btn wizard-prev" type="button">${wizardCfg.prevLabel || defaults.prevLabel}</button>
            <button class="btn primary wizard-next" type="button">${wizardCfg.nextLabel || defaults.nextLabel}</button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const closeBtn = overlay.querySelector('.wizard-close');
    const prevBtn = overlay.querySelector('.wizard-prev');
    const nextBtn = overlay.querySelector('.wizard-next');
    const skipBtn = overlay.querySelector('.wizard-skip');
    const titleEl = overlay.querySelector('.wizard-step-title');
    const bodyEl = overlay.querySelector('.wizard-step-body');
    const iconEl = overlay.querySelector('.wizard-step-icon');
    const dots = Array.from(overlay.querySelectorAll('.wizard-progress span'));

    let currentIndex = 0;

    const setStep = index => {
      currentIndex = Math.max(0, Math.min(index, steps.length - 1));
      const step = steps[currentIndex];
      titleEl.textContent = step.title || '';

      if (step.icon) {
        iconEl.textContent = step.icon;
        iconEl.classList.remove('hidden');
      } else {
        iconEl.textContent = '';
        iconEl.classList.add('hidden');
      }

      bodyEl.innerHTML = '';
      if (step.html) {
        bodyEl.innerHTML = step.html;
      } else {
        if (step.description) {
          const p = document.createElement('p');
          p.textContent = step.description;
          bodyEl.appendChild(p);
        }
        if (Array.isArray(step.bullets) && step.bullets.length) {
          const ul = document.createElement('ul');
          step.bullets.forEach(item => {
            const li = document.createElement('li');
            li.textContent = item;
            ul.appendChild(li);
          });
          bodyEl.appendChild(ul);
        }
        if (Array.isArray(step.extra) && step.extra.length) {
          step.extra.forEach(node => {
            if (typeof node === 'string') {
              const p = document.createElement('p');
              p.textContent = node;
              bodyEl.appendChild(p);
            }
          });
        }
      }

      prevBtn.disabled = currentIndex === 0;
      const nextLabel = currentIndex === steps.length - 1
        ? (step.doneLabel || wizardCfg.doneLabel || defaults.doneLabel)
        : (step.nextLabel || wizardCfg.nextLabel || defaults.nextLabel);
      nextBtn.textContent = nextLabel;
      dots.forEach((dot, idx) => {
        dot.classList.toggle('active', idx <= currentIndex);
        dot.setAttribute('aria-current', idx === currentIndex ? 'step' : 'false');
      });
    };

    const hide = (mark = false) => {
      overlay.classList.add('hidden');
      document.body.classList.remove('wizard-open');
      if (mark) {
        markSeen();
      }
      document.removeEventListener('keydown', onKeyDown);
    };

    const show = (startIndex = 0) => {
      setStep(startIndex);
      overlay.classList.remove('hidden');
      document.body.classList.add('wizard-open');
      document.addEventListener('keydown', onKeyDown);
      nextBtn.focus({ preventScroll: true });
    };

    const goNext = () => {
      if (currentIndex >= steps.length - 1) {
        hide(true);
        return;
      }
      setStep(currentIndex + 1);
    };

    const goPrev = () => {
      if (currentIndex > 0) {
        setStep(currentIndex - 1);
      }
    };

    const onKeyDown = evt => {
      if (evt.key === 'Escape') {
        evt.preventDefault();
        hide(true);
      } else if (evt.key === 'ArrowRight') {
        evt.preventDefault();
        goNext();
      } else if (evt.key === 'ArrowLeft') {
        evt.preventDefault();
        goPrev();
      }
    };

    nextBtn.addEventListener('click', goNext);
    prevBtn.addEventListener('click', goPrev);
    skipBtn.addEventListener('click', () => hide(true));
    closeBtn.addEventListener('click', () => hide(true));
    overlay.addEventListener('click', evt => {
      if (evt.target === overlay) {
        hide(true);
      }
    });
    dots.forEach((dot, idx) => {
      dot.addEventListener('click', () => {
        setStep(idx);
      });
    });
    wizardInstance = {
      show,
      hide,
      isVisible: () => !overlay.classList.contains('hidden')
    };

    return wizardInstance;
  }

  function waitForAppReady(callback) {
    const root = document.getElementById('appRoot');
    if (!root) {
      callback();
      return;
    }
    if (!root.classList.contains('hidden')) {
      callback();
      return;
    }
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      callback();
    };
    const observer = new MutationObserver(() => {
      if (!root.classList.contains('hidden')) {
        observer.disconnect();
        finish();
      }
    });
    observer.observe(root, { attributes: true, attributeFilter: ['class'] });
    const timeout = Number.isFinite(wizardCfg.fallbackDelayMs) ? wizardCfg.fallbackDelayMs : defaults.fallbackDelayMs;
    if (timeout > 0) {
      setTimeout(() => {
        try { observer.disconnect(); } catch (_) {}
        finish();
      }, timeout);
    }
  }

  function autoShow() {
    if (!autoShowEnabled) {
      return;
    }
    if (hasSeen() && !showEvenIfSeen) {
      return;
    }
    waitForAppReady(() => {
      const instance = ensureWizard();
      if (!instance.isVisible()) {
        instance.show(0);
      }
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    autoShow();
    const selector = wizardCfg.reopenSelector || defaults.reopenSelector;
    if (selector) {
      document.querySelectorAll(selector).forEach(btn => {
        btn.addEventListener('click', evt => {
          evt.preventDefault();
          const instance = ensureWizard();
          instance.show(0);
          try { btn.closest('.dropdown')?.classList.add('hidden'); } catch (_) {}
        });
      });
    }
  });
})();