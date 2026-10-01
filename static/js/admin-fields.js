// Admin form widgets: image fields (paste a URL or upload), image lists, social-link lists.
// Progressive enhancement: the underlying inputs keep working without this script.
(function () {
    const IMAGE_EXTS = '.png,.jpg,.jpeg,.gif,.webp,.avif';

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text) node.textContent = text;
        return node;
    }

    async function uploadImage(file, slug) {
        const body = new FormData();
        body.append('slug', slug || 'upload');
        body.append('file_count', '0');
        body.append('file', file);
        const res = await fetch('/admin/upload', { method: 'POST', body });
        if (!res.ok) throw new Error(res.status === 415 ? 'unsupported file type' : `HTTP ${res.status}`);
        const data = await res.json();
        if (!data.success || !data.url) throw new Error('upload failed');
        return data.url;
    }

    // Wraps a text input with a preview thumbnail and an Upload button.
    function enhanceImageInput(input, slugSource, onChange) {
        const wrap = el('div', 'img-field');
        const row = el('div', 'img-field-row');
        const preview = el('img', 'img-field-preview');
        preview.alt = '';
        preview.hidden = true;
        const button = el('button', 'img-field-btn', 'Upload');
        button.type = 'button';
        const status = el('div', 'img-field-status');
        const picker = el('input');
        picker.type = 'file';
        picker.accept = IMAGE_EXTS;
        picker.hidden = true;

        input.parentNode.insertBefore(wrap, input);
        row.append(preview, input, button, picker);
        wrap.append(row, status);

        const refresh = () => {
            const url = input.value.trim();
            preview.hidden = !url;
            if (url) preview.src = url;
            if (onChange) onChange();
        };
        preview.addEventListener('error', () => { preview.hidden = true; });
        input.addEventListener('input', refresh);
        button.addEventListener('click', () => picker.click());
        picker.addEventListener('change', async () => {
            const file = picker.files && picker.files[0];
            picker.value = '';
            if (!file) return;
            const slug = slugSource ? (document.querySelector(slugSource) || {}).value : '';
            status.textContent = 'Uploading...';
            button.disabled = true;
            try {
                input.value = await uploadImage(file, slug);
                status.textContent = '';
                input.dispatchEvent(new Event('input', { bubbles: true }));
            } catch (err) {
                status.textContent = `Upload failed: ${err.message}`;
            } finally {
                button.disabled = false;
            }
        });
        refresh();
    }

    document.querySelectorAll('[data-image-field]').forEach((box) => {
        const input = box.querySelector('input');
        if (input) enhanceImageInput(input, box.dataset.slugFrom);
    });

    // A comma-separated `images` input becomes a list of image fields with "+ Add image".
    document.querySelectorAll('[data-image-list]').forEach((box) => {
        const store = box.querySelector('input');
        if (!store) return;
        const slugSource = box.dataset.slugFrom;
        const initial = store.value.split(',').map((u) => u.trim()).filter(Boolean);
        store.type = 'hidden';

        const list = el('div', 'img-list');
        const add = el('button', 'img-list-add', '+ Add image');
        add.type = 'button';
        store.after(list, add);

        const sync = () => {
            store.value = Array.from(list.querySelectorAll('input'))
                .map((i) => i.value.trim())
                .filter(Boolean)
                .join(', ');
        };
        const addRow = (value) => {
            const item = el('div', 'img-list-item');
            const input = el('input', 'img-list-input');
            input.type = 'text';
            input.placeholder = 'Paste image URL or upload';
            input.value = value || '';
            item.append(input);
            list.append(item);
            enhanceImageInput(input, slugSource, sync);
            const remove = el('button', 'img-list-remove', '×');
            remove.type = 'button';
            remove.title = 'Remove image';
            remove.addEventListener('click', () => { item.remove(); sync(); });
            item.append(remove);
        };
        initial.forEach(addRow);
        add.addEventListener('click', () => addRow(''));
    });

    // Avatar framing: drag to move, slider to zoom. Stores the image's width/left/top as
    // percentages of the round frame (photo_w/photo_l/photo_t), so it looks the same at any size.
    document.querySelectorAll('[data-avatar-editor]').forEach((box) => {
        const form = box.closest('form');
        const photo = form && form.querySelector('input[name="photo_url"]');
        const stage = box.querySelector('.avatar-stage');
        const img = stage && stage.querySelector('img');
        const zoom = box.querySelector('.avatar-zoom');
        const fw = box.querySelector('input[name="photo_w"]');
        const fl = box.querySelector('input[name="photo_l"]');
        const ft = box.querySelector('input[name="photo_t"]');
        if (!photo || !img || !zoom || !fw || !fl || !ft) return;

        const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
        const parse = (v, fallback) => { const n = parseFloat(v); return Number.isFinite(n) ? n : fallback; };
        let W = fw.value.trim() === '' ? null : parse(fw.value, null);
        let L = parse(fl.value, 0);
        let T = parse(ft.value, 0);
        let lastUrl = photo.value.trim();

        const ready = () => img.naturalWidth > 0 && img.naturalHeight > 0;
        const cover = () => 100 * Math.max(1, img.naturalWidth / img.naturalHeight);
        const height = () => W * img.naturalHeight / img.naturalWidth;
        const fit = () => { L = clamp(L, 100 - W, 0); T = clamp(T, 100 - height(), 0); };
        const render = () => {
            img.style.cssText = `position:absolute;max-width:none;height:auto;width:${W}%;left:${L}%;top:${T}%`;
            zoom.value = String(clamp(W / cover(), 1, 4));
        };
        const save = () => {
            fw.value = W.toFixed(2);
            fl.value = L.toFixed(2);
            ft.value = T.toFixed(2);
        };
        const center = () => { W = cover(); L = (100 - W) / 2; T = (100 - height()) / 2; };
        const init = () => {
            if (!ready()) return;
            if (W === null) center();
            fit();
            render();
        };
        const sync = () => {
            const url = photo.value.trim();
            box.hidden = !url;
            if (url !== lastUrl) {
                lastUrl = url;
                W = null; L = 0; T = 0;
                fw.value = ''; fl.value = '0'; ft.value = '0';
                img.style.cssText = '';
            }
            if (url) img.src = url;
        };

        img.addEventListener('load', init);
        photo.addEventListener('input', sync);
        sync();
        if (img.complete) init();

        let drag = null;
        stage.addEventListener('pointerdown', (e) => {
            if (!ready() || W === null) return;
            stage.setPointerCapture(e.pointerId);
            stage.classList.add('dragging');
            drag = { x: e.clientX, y: e.clientY, L, T, size: stage.clientWidth || 1 };
        });
        stage.addEventListener('pointermove', (e) => {
            if (!drag) return;
            L = drag.L + (e.clientX - drag.x) / drag.size * 100;
            T = drag.T + (e.clientY - drag.y) / drag.size * 100;
            fit(); render(); save();
        });
        const end = () => { drag = null; stage.classList.remove('dragging'); };
        stage.addEventListener('pointerup', end);
        stage.addEventListener('pointercancel', end);

        zoom.addEventListener('input', () => {
            if (!ready() || W === null) return;
            // Zoom around whatever is currently at the centre of the frame.
            const u = (50 - L) / W;
            const v = (50 - T) / height();
            W = cover() * clamp(parseFloat(zoom.value) || 1, 1, 4);
            L = 50 - u * W;
            T = 50 - v * height();
            fit(); render(); save();
        });
    });

    // Social links: rows of {platform, url}, serialised as JSON into the hidden `links` input.
    document.querySelectorAll('[data-links-editor]').forEach((box) => {
        const store = box.querySelector('input[name="links"]');
        const rows = box.querySelector('.links-rows');
        const template = box.querySelector('template');
        const add = box.querySelector('.links-add');
        if (!store || !rows || !template || !add) return;

        const sync = () => {
            const links = Array.from(rows.querySelectorAll('.link-row'))
                .map((row) => ({
                    platform: row.querySelector('select').value,
                    url: row.querySelector('input').value.trim(),
                }))
                .filter((l) => l.url);
            store.value = JSON.stringify(links);
        };
        const addRow = (link) => {
            const row = template.content.firstElementChild.cloneNode(true);
            if (link) {
                row.querySelector('select').value = link.platform;
                row.querySelector('input').value = link.url;
            }
            row.querySelector('.link-remove').addEventListener('click', () => { row.remove(); sync(); });
            row.addEventListener('input', sync);
            row.addEventListener('change', sync);
            rows.append(row);
        };

        try { JSON.parse(store.value || '[]').forEach(addRow); } catch (_) { /* start empty */ }
        add.addEventListener('click', () => { addRow(); sync(); });
        sync();
    });
})();
