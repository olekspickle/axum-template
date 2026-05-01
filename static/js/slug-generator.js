const titleInput = document.getElementById('title-input');
const slugInput = document.getElementById('slug-input');

function toKebabCase(str) {
    return str
        .toLowerCase()
        .trim()
        .replace(/[^\w\s-]/g, '')
        .replace(/[\s_-]+/g, '-')
        .replace(/^-+|-+$/g, '');
}

if (titleInput && slugInput) {
    function enableManual() {
        slugInput.classList.remove('text-gray-400');
    }

    if (!slugInput.dataset.manual) {
        slugInput.classList.add('text-gray-400');
        slugInput.value = toKebabCase(titleInput.value);
    } else {
        enableManual();
    }

    titleInput.addEventListener('input', () => {
        if (!slugInput.dataset.manual) {
            slugInput.value = toKebabCase(titleInput.value);
        }
    });

    slugInput.addEventListener('input', () => {
        slugInput.dataset.manual = 'true';
        enableManual();
        slugInput.value = toKebabCase(slugInput.value);
    });
}

const contentInput = document.getElementById('content-input');
const excerptInput = document.getElementById('excerpt-input');

if (contentInput && excerptInput) {
    function enableExcerptManual() {
        excerptInput.classList.remove('text-gray-400');
    }

    function generateExcerpt() {
        if (!excerptInput.dataset.manual) {
            const text = contentInput.value.replace(/[#*_`\[\]]/g, '').trim();
            excerptInput.value = text.substring(0, 200);
        }
    }

    if (!excerptInput.value) {
        excerptInput.classList.add('text-gray-400');
        generateExcerpt();
    } else {
        enableExcerptManual();
    }

    contentInput.addEventListener('input', generateExcerpt);

    excerptInput.addEventListener('input', () => {
        excerptInput.dataset.manual = 'true';
        enableExcerptManual();
    });
}