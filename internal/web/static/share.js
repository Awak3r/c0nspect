(() => {
  function startCopy(request) {
    const clipboard = navigator.clipboard;
    if (!clipboard) return Promise.resolve(false);
    if (clipboard.write && typeof ClipboardItem === 'function') {
      // WebKit needs the write to start during the click, before the fetch completes.
      const contents = request.then(url => new Blob([url], { type: 'text/plain' }));
      contents.catch(() => {});
      try {
        return clipboard.write([new ClipboardItem({ 'text/plain': contents })]).then(() => true, () => false);
      } catch {
        // Older implementations may not accept a promise in ClipboardItem.
      }
    }
    return request.then(url => clipboard.writeText(url)).then(() => true, () => false);
  }

  for (const form of document.querySelectorAll('form[data-quick-share]')) {
    const row = form.closest('li');
    const status = row.querySelector('[data-share-status]');
    const mark = row.querySelector('[data-share-mark]');
    const manual = row.querySelector('[data-share-url]');
    const button = form.querySelector('button');
    let pending = false;

    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (pending) return;
      pending = true;
      button.setAttribute('aria-disabled', 'true');
      manual.hidden = true;
      manual.value = '';
      status.textContent = 'Готовим ссылку…';

      let failureMessage = 'Не удалось получить ссылку. Попробуйте ещё раз.';
      try {
        // The hidden input named "action" shadows the form.action property.
        const request = fetch(form.getAttribute('action'), {
          method: 'POST',
          headers: { Accept: 'application/json' },
          body: new URLSearchParams(new FormData(form)),
          mode: 'same-origin',
          redirect: 'error',
        }).then(async response => {
          if (response.status === 409) {
            failureMessage = 'Прежнюю ссылку нельзя скопировать. Перевыпустите её в настройках конспекта.';
          }
          if (!response.ok) throw new Error();
          const { url } = await response.json();
          if (typeof url !== 'string' || !url) throw new Error();
          return url;
        });

        const copy = startCopy(request);
        const url = await request;
        if (mark) mark.hidden = false;
        if (await copy) {
          status.textContent = 'Ссылка скопирована';
        } else {
          status.textContent = 'Не удалось скопировать автоматически. Скопируйте ссылку из поля ниже.';
          manual.value = url;
          manual.hidden = false;
        }
      } catch {
        status.textContent = failureMessage;
      } finally {
        button.removeAttribute('aria-disabled');
        pending = false;
      }
    });
  }
})();
