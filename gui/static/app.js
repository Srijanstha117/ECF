// Container list conveniences: search, sort, and whole-row clicks.
// Everything still works without this file.
(function () {
    "use strict";

    var table = document.getElementById("list");
    if (!table) return;
    var tbody = table.tBodies[0];

    // Whole-row click, without hijacking clicks on the link itself or
    // text selection.
    tbody.addEventListener("click", function (event) {
        if (event.target.closest("a")) return;
        if (window.getSelection && String(window.getSelection())) return;
        var row = event.target.closest("tr");
        var link = row && row.querySelector("a.name-link");
        if (link) window.location.href = link.href;
    });

    var filter = document.getElementById("filter");
    var empty = document.getElementById("filter-empty");
    if (filter) {
        filter.addEventListener("input", function () {
            var q = filter.value.trim().toLowerCase();
            var shown = 0;
            Array.prototype.forEach.call(tbody.rows, function (row) {
                var match = !q || row.dataset.name.indexOf(q) !== -1;
                row.hidden = !match;
                if (match) shown += 1;
            });
            if (empty) empty.hidden = shown !== 0;
        });
    }

    // Sorting: aria-sort lives on the <th>, where assistive tech reads it.
    var buttons = table.querySelectorAll("button.sort");
    buttons.forEach(function (button) {
        button.addEventListener("click", function () {
            var key = button.dataset.sort;
            var th = button.closest("th");
            var ascending = th.getAttribute("aria-sort") !== "ascending";
            buttons.forEach(function (b) { b.closest("th").removeAttribute("aria-sort"); });
            th.setAttribute("aria-sort", ascending ? "ascending" : "descending");

            var rows = Array.prototype.slice.call(tbody.rows);
            rows.sort(function (a, b) {
                var av, bv;
                if (key === "lifetime") {
                    // Unknown lifetimes always sink to the bottom.
                    av = a.dataset.lifetime === "" ? Infinity : parseFloat(a.dataset.lifetime);
                    bv = b.dataset.lifetime === "" ? Infinity : parseFloat(b.dataset.lifetime);
                    if (av === Infinity || bv === Infinity) return av === bv ? 0 : (av === Infinity ? 1 : -1);
                    return ascending ? av - bv : bv - av;
                }
                av = a.dataset.name; bv = b.dataset.name;
                return ascending ? av.localeCompare(bv) : bv.localeCompare(av);
            });
            rows.forEach(function (row) { tbody.appendChild(row); });
        });
    });
})();
