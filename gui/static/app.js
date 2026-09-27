// Dashboard behaviour: listener status, the live "Running now" panel,
// and list filter / sort / row clicks. Pages still work without it.
(function () {
    "use strict";

    // A 401 means the session ran out while the page was open.
    function getJSON(url) {
        return fetch(url, { cache: "no-store", credentials: "same-origin" }).then(function (r) {
            if (r.status === 401) {
                window.location.href = "/login?next=" + encodeURIComponent(location.pathname + location.search);
                throw new Error("signed out");
            }
            return r.json();
        });
    }

    function formatBytes(value, perSecond) {
        var units = ["B", "KiB", "MiB", "GiB", "TiB"], i = 0;
        value = value || 0;
        while (Math.abs(value) >= 1024 && i < units.length - 1) { value /= 1024; i++; }
        return (i === 0 ? value.toFixed(0) : value.toFixed(1)) + " " + units[i] + (perSecond ? "/s" : "");
    }

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    // ---------------------------------------------------------- wide tables
    // A table wider than its panel scrolls inside the panel, never the page.
    var wraps = document.querySelectorAll(".table-wrap");
    var fitTables = function () {
        wraps.forEach(function (wrap) {
            var table = wrap.querySelector("table");
            if (!table) return;
            wrap.classList.remove("is-too-wide");
            wrap.classList.toggle("is-too-wide", table.scrollWidth > wrap.clientWidth + 1);
        });
    };
    if (wraps.length) {
        fitTables();
        window.addEventListener("resize", fitTables);
    }

    // ---------------------------------------------------------- search suggestions
    // After a couple of characters, up to four suggestions drop down under
    // the search box: containers (open their page) and ports, endings or
    // dates (open the search). Arrow keys move, Enter opens, Escape closes;
    // Enter with nothing highlighted still runs the full search.
    var searchBox = document.getElementById("shell-q");
    var suggestList = document.getElementById("shell-suggest");
    if (searchBox && suggestList) {
        var suggestStatus = document.getElementById("shell-suggest-status");
        var items = [];
        var active = -1;
        var timer = null;
        var lastAsked = "";

        var closeSuggestions = function () {
            suggestList.hidden = true;
            suggestList.textContent = "";
            searchBox.setAttribute("aria-expanded", "false");
            searchBox.removeAttribute("aria-activedescendant");
            items = [];
            active = -1;
        };
        var highlight = function (text, typed) {
            // The typed part in bold, built as text (names come from evidence).
            var span = el("span", "suggest-label");
            var at = text.toLowerCase().indexOf(typed.toLowerCase());
            if (at < 0 || !typed) { span.textContent = text; return span; }
            span.appendChild(document.createTextNode(text.slice(0, at)));
            span.appendChild(el("strong", "", text.slice(at, at + typed.length)));
            span.appendChild(document.createTextNode(text.slice(at + typed.length)));
            return span;
        };
        var setActive = function (index) {
            var options = suggestList.querySelectorAll("[role=option]");
            if (!options.length) return;
            active = (index + options.length) % options.length;
            options.forEach(function (option, i) { option.setAttribute("aria-selected", i === active ? "true" : "false"); });
            searchBox.setAttribute("aria-activedescendant", options[active].id);
        };
        var showSuggestions = function (typed, suggestions) {
            suggestList.textContent = "";
            items = suggestions;
            active = -1;
            searchBox.removeAttribute("aria-activedescendant");
            if (!suggestions.length) {
                suggestList.hidden = true;
                searchBox.setAttribute("aria-expanded", "false");
                suggestStatus.textContent = "No suggestions. Press Enter to search.";
                return;
            }
            suggestions.forEach(function (s, i) {
                var option = el("li", "suggest-item");
                option.id = "shell-suggest-" + i;
                option.setAttribute("role", "option");
                option.setAttribute("aria-selected", "false");
                option.appendChild(el("span", "suggest-kind", s.kind));
                var text = el("span", "suggest-text");
                text.appendChild(highlight(s.label, typed));
                text.appendChild(el("span", "suggest-detail", s.detail));
                option.appendChild(text);
                // mousedown, not click: fires before the box loses focus.
                option.addEventListener("mousedown", function (event) {
                    event.preventDefault();
                    window.location.href = s.url;
                });
                option.addEventListener("mousemove", function () { if (active !== i) setActive(i); });
                suggestList.appendChild(option);
            });
            suggestList.hidden = false;
            searchBox.setAttribute("aria-expanded", "true");
            suggestStatus.textContent = suggestions.length + " suggestion" + (suggestions.length === 1 ? "" : "s") +
                ". Use the arrow keys to choose one.";
        };
        var askForSuggestions = function () {
            var typed = searchBox.value.trim();
            if (typed.length < 2) { closeSuggestions(); lastAsked = ""; return; }
            if (typed === lastAsked && !suggestList.hidden) return;
            lastAsked = typed;
            getJSON(searchBox.dataset.suggestUrl + "?q=" + encodeURIComponent(typed)).then(function (data) {
                // Ignore a slow answer to something no longer in the box.
                if (data.q.trim() === searchBox.value.trim() && document.activeElement === searchBox) {
                    showSuggestions(typed, data.suggestions);
                }
            }).catch(function () {});
        };

        searchBox.addEventListener("input", function () {
            clearTimeout(timer);
            timer = setTimeout(askForSuggestions, 150);
        });
        searchBox.addEventListener("focus", function () {
            if (searchBox.value.trim().length >= 2) { lastAsked = ""; askForSuggestions(); }
        });
        searchBox.addEventListener("keydown", function (event) {
            if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                if (suggestList.hidden) { lastAsked = ""; askForSuggestions(); return; }
                event.preventDefault();
                setActive(active + (event.key === "ArrowDown" ? 1 : -1));
            } else if (event.key === "Enter" && active >= 0 && items[active]) {
                event.preventDefault();
                window.location.href = items[active].url;
            } else if (event.key === "Escape" && !suggestList.hidden) {
                event.preventDefault();  // keep the text; only close the list
                closeSuggestions();
            }
        });
        searchBox.addEventListener("blur", function () { setTimeout(closeSuggestions, 100); });
    }

    // ---------------------------------------------------------- listener status
    var status = document.getElementById("listener-status");
    var starting = false;
    var stopping = false;
    function showListener(listener) {
        if (!status) return;
        var startButton = status.querySelector(".listener-start");
        status.className = "listener listener-" + listener.state;
        status.querySelector(".listener-label").textContent = listener.label;
        status.querySelector(".listener-sub").textContent =
            starting && listener.state !== "running" ? "starting..." : listener.sub;
        if (listener.state === "running" || listener.state === "waiting") starting = false;
        startButton.hidden = listener.state === "running" || listener.state === "waiting" || starting;
        status.querySelector(".listener-stop").hidden = !(listener.state === "running" || listener.state === "waiting") || stopping;
        if (listener.state !== "running" && listener.state !== "waiting") stopping = false;
    }
    if (status) {
        var pageSig = status.dataset.evidenceSig;
        var refresh = status.querySelector(".listener-refresh");
        var startButton = status.querySelector(".listener-start");
        startButton.addEventListener("click", function () {
            starting = true;
            startButton.hidden = true;
            status.querySelector(".listener-sub").textContent = "starting...";
            fetch(startButton.dataset.startUrl, { method: "POST", credentials: "same-origin" })
                .then(function (r) { return r.json(); })
                .then(function (s) {
                    if (!s.started && s.message !== "already running" && s.message !== "starting") {
                        starting = false;
                        showListener(s.listener);
                        status.querySelector(".listener-sub").textContent = "couldn't start: " + s.message;
                    }
                })
                .catch(function () { starting = false; startButton.hidden = false; });
            setTimeout(function () { starting = false; }, 20000);
        });
        var stopButton = status.querySelector(".listener-stop");
        stopButton.addEventListener("click", function () {
            if (!window.confirm("Stop the listener? Containers that die while it's stopped won't be captured.")) return;
            stopping = true;
            stopButton.hidden = true;
            status.querySelector(".listener-sub").textContent = "stopping...";
            fetch(stopButton.dataset.stopUrl, { method: "POST", credentials: "same-origin" })
                .then(function (r) { return r.json(); })
                .then(function (s) { if (!s.stopping) { stopping = false; showListener(s.listener); } })
                .catch(function () { stopping = false; stopButton.hidden = false; });
            setTimeout(function () { stopping = false; }, 15000);
        });
        // On the dashboard, the live panel's poll carries the status too.
        if (!document.getElementById("live-panel")) {
            setInterval(function () {
                getJSON(status.dataset.statusUrl).then(function (s) {
                    showListener(s.listener);
                    refresh.hidden = s.evidence_sig === pageSig;
                }).catch(function () {});
            }, 3000);
        }
    }

    // ---------------------------------------------------------- live panel
    var livePanel = document.getElementById("live-panel");
    if (livePanel) {
        var rowsBody = document.getElementById("live-rows");
        var empty = document.getElementById("live-empty");
        var updated = document.getElementById("live-updated");
        var running = document.getElementById("kpi-running");
        var history = {};  // container id -> recent CPU %, for the sparkline
        var HISTORY = 30;

        var sparkline = function (values) {
            var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
            svg.setAttribute("class", "spark");
            svg.setAttribute("viewBox", "0 0 100 20");
            svg.setAttribute("preserveAspectRatio", "none");
            svg.setAttribute("aria-hidden", "true");
            if (values.length > 1) {
                var top = Math.max(100, Math.max.apply(null, values));
                var line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
                line.setAttribute("points", values.map(function (v, i) {
                    return (i / (HISTORY - 1) * 100).toFixed(2) + "," + (20 - v / top * 20).toFixed(2);
                }).join(" "));
                svg.appendChild(line);
            }
            return svg;
        };

        var meterCell = function (cls, pct, text, extra) {
            var td = el("td", cls);
            var meter = el("span", "meter");
            var fill = el("span", "meter-fill");
            fill.style.setProperty("--pct", (Math.max(0, Math.min(100, pct)) / 100).toFixed(3));
            meter.appendChild(fill);
            td.appendChild(meter);
            td.appendChild(el("span", "meter-val", text));
            if (extra) td.appendChild(extra);
            return td;
        };

        var render = function (data) {
            showListener(data.listener);
            if (status) status.querySelector(".listener-refresh").hidden = data.evidence_sig === status.dataset.evidenceSig;
            var live = data.live || [];
            rowsBody.textContent = "";
            live.forEach(function (c) {
                var h = history[c.id] = (history[c.id] || []).concat([c.cpu_pct]).slice(-HISTORY);
                var tr = el("tr");
                var name = el("td");
                name.appendChild(el("strong", "data", c.name));
                name.appendChild(el("small", "data", c.id + (c.pids ? " · " + c.pids + " process" + (c.pids === 1 ? "" : "es") : "")));
                tr.appendChild(name);
                tr.appendChild(meterCell("col-cpu", c.cpu_pct, c.cpu_pct.toFixed(1) + "%", sparkline(h)));
                var memPct = c.mem_limit_bytes ? c.mem_bytes / c.mem_limit_bytes * 100 : 0;
                tr.appendChild(meterCell("col-mem", memPct, formatBytes(c.mem_bytes) +
                    (c.mem_limit_bytes ? " of " + formatBytes(c.mem_limit_bytes) : "")));
                var net = el("td", "nowrap");
                net.appendChild(el("span", "net-in", "↓ " + formatBytes(c.rx_rate, true)));
                net.appendChild(document.createTextNode(" "));
                net.appendChild(el("span", "net-out", "↑ " + formatBytes(c.tx_rate, true)));
                tr.appendChild(net);
                rowsBody.appendChild(tr);
            });
            empty.hidden = live.length > 0;
            if (!live.length) {
                empty.textContent = data.listener.state === "running"
                    ? "No containers are running. Start one and it appears here within a second."
                    : "Live figures come from the capture listener, which isn't running. Start it from the header.";
            }
            if (running) running.textContent = data.listener.state === "running" ? live.length : "—";
            var tile = document.getElementById("kpi-listener-tile");
            if (tile) {
                var st = data.listener.state;
                tile.className = "kpi kpi-" + st;
                document.getElementById("kpi-listener").textContent =
                    st === "running" ? "Running" : st === "waiting" ? "Waiting for Docker" : "Off";
                document.getElementById("kpi-listener-sub").textContent = data.listener.sub;
            }
            updated.textContent = "live · updated " + new Date(data.at * 1000).toLocaleTimeString();
        };
        var poll = function () { getJSON(livePanel.dataset.liveUrl).then(render).catch(function () {}); };
        poll();
        setInterval(poll, 2000);
    }

    // ---------------------------------------------------------- container list
    var table = document.getElementById("list");
    if (!table) return;
    var tbody = table.tBodies[0];

    tbody.addEventListener("click", function (event) {
        if (event.target.closest("a")) return;
        if (window.getSelection && String(window.getSelection())) return;
        var row = event.target.closest("tr");
        var link = row && row.querySelector("a.name-link");
        if (link) window.location.href = link.href;
    });

    var filter = document.getElementById("filter");
    var noMatch = document.getElementById("filter-empty");
    if (filter) {
        filter.addEventListener("input", function () {
            var q = filter.value.trim().toLowerCase();
            var shown = 0;
            Array.prototype.forEach.call(tbody.rows, function (row) {
                var match = !q || row.dataset.name.indexOf(q) !== -1;
                row.hidden = !match;
                if (match) shown += 1;
            });
            if (noMatch) noMatch.hidden = shown !== 0;
        });
    }

    var numeric = function (row, key) {
        var v = row.dataset[key];
        return v === "" || v === undefined ? null : parseFloat(v);
    };
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
                if (key === "name") {
                    return ascending ? a.dataset.name.localeCompare(b.dataset.name) : b.dataset.name.localeCompare(a.dataset.name);
                }
                var av = numeric(a, key), bv = numeric(b, key);
                if (av === null || bv === null) return av === bv ? 0 : (av === null ? 1 : -1);
                return ascending ? av - bv : bv - av;
            });
            rows.forEach(function (row) { tbody.appendChild(row); });
        });
    });
})();
