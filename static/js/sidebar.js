(function () {
    var aside = document.getElementById('admin-sidebar');
    if (!aside) {
        return;
    }
    var KEY = 'admin-sidebar-collapsed';
    var collapsed = localStorage.getItem(KEY) === '1';
    var title = document.getElementById('sidebar-title');
    var footer = document.getElementById('sidebar-footer');
    var nav = document.getElementById('sidebar-nav');
    var toggle = document.getElementById('sidebar-toggle');
    var toggleIcon = toggle ? toggle.querySelector('i') : null;
    var links = nav ? nav.querySelectorAll('a, button') : [];
    var labels = aside.querySelectorAll('.sidebar-label');

    function apply(c) {
        aside.classList.toggle('w-16', c);
        aside.classList.toggle('w-64', !c);
        aside.classList.toggle('p-3', c);
        aside.classList.toggle('p-6', !c);
        if (toggleIcon) {
            toggleIcon.classList.toggle('rotate-180', c);
        }
        if (footer) {
            footer.classList.toggle('justify-center', c);
            footer.classList.toggle('justify-end', !c);
        }
        if (title) {
            title.style.display = c ? 'none' : '';
        }
        links.forEach(function (el) {
            el.classList.toggle('justify-center', c);
            el.classList.toggle('px-0', c);
            el.classList.toggle('gap-0', c);
        });
        labels.forEach(function (label) {
            label.style.display = c ? 'none' : '';
        });
        if (toggle) {
            toggle.title = c ? 'Expand sidebar' : 'Minimize sidebar';
        }
    }

    apply(collapsed);

    if (toggle) {
        toggle.addEventListener('click', function (e) {
            e.preventDefault();
            collapsed = !collapsed;
            localStorage.setItem(KEY, collapsed ? '1' : '0');
            apply(collapsed);
        });
    }
})();