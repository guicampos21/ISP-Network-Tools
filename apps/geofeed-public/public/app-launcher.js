"use strict";

(function () {
    var launcher = document.querySelector('[data-app-launcher]');
    if (!launcher) return;
    var trigger = launcher.querySelector('[data-launcher-trigger]');
    var search = launcher.querySelector('[data-launcher-search]');
    var items = Array.prototype.slice.call(launcher.querySelectorAll('[data-launcher-item]'));
    var empty = launcher.querySelector('[data-launcher-empty]');
    function filterApplications() {
        var query = (search.value || '').trim().toLocaleLowerCase('pt-BR');
        var visible = 0;
        items.forEach(function (item) {
            var matches = !query || (item.getAttribute('data-app-label') || '').toLocaleLowerCase('pt-BR').indexOf(query) !== -1;
            item.hidden = !matches;
            if (matches) visible += 1;
        });
        if (empty) empty.hidden = visible > 0;
    }
    search.addEventListener('input', filterApplications);
    launcher.querySelector('[data-launcher-close]').addEventListener('click', function () {
        launcher.removeAttribute('open');
        trigger.focus();
    });
    launcher.addEventListener('toggle', function () {
        var open = launcher.open;
        trigger.setAttribute('aria-expanded', String(open));
        if (open) window.requestAnimationFrame(function () { search.focus(); });
        else search.value = '';
        if (!open) filterApplications();
    });
    document.addEventListener('click', function (event) {
        if (!launcher.contains(event.target)) launcher.removeAttribute('open');
    });
    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape' && launcher.open) {
            launcher.removeAttribute('open');
            trigger.focus();
        }
    });
}());
