// MailShield front-end interactions: sample loading, clearing the form,
// and a client-side size check on file uploads. Deliberately plain JS,
// no build step and no external libraries.
(function () {
    "use strict";

    var MAX_TEXT_BYTES = 1 * 1024 * 1024;
    var MAX_IMAGE_BYTES = 5 * 1024 * 1024;
    var TEXT_EXTENSIONS = [".eml", ".txt"];
    var IMAGE_EXTENSIONS = [".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"];

    function qs(selector) { return document.querySelector(selector); }

    function initSampleDropdown() {
        var toggleBtn = qs("#load-sample-btn");
        var menu = qs("#sample-menu");
        var textarea = qs("#headers");
        if (!toggleBtn || !menu || !textarea) return;

        toggleBtn.addEventListener("click", function (event) {
            event.stopPropagation();
            menu.hidden = !menu.hidden;
        });

        document.addEventListener("click", function () {
            menu.hidden = true;
        });

        Array.prototype.forEach.call(menu.querySelectorAll(".dropdown-item"), function (item) {
            item.addEventListener("click", function () {
                var name = item.getAttribute("data-sample");
                fetch("/sample/" + encodeURIComponent(name))
                    .then(function (res) { return res.json(); })
                    .then(function (data) {
                        if (data && data.content) {
                            textarea.value = data.content;
                        }
                    })
                    .catch(function () {
                        // Silently ignore -- the user can still paste headers manually.
                    });
                menu.hidden = true;
            });
        });
    }

    function initClearButton() {
        var clearBtn = qs("#clear-btn");
        var textarea = qs("#headers");
        var fileInput = qs("#file");
        if (!clearBtn) return;
        clearBtn.addEventListener("click", function () {
            if (textarea) textarea.value = "";
            if (fileInput) fileInput.value = "";
            var errorEl = qs("#upload-error");
            if (errorEl) errorEl.hidden = true;
        });
    }

    function initFileValidation() {
        var fileInput = qs("#file");
        var errorEl = qs("#upload-error");
        if (!fileInput || !errorEl) return;

        fileInput.addEventListener("change", function () {
            errorEl.hidden = true;
            errorEl.textContent = "";
            var file = fileInput.files && fileInput.files[0];
            if (!file) return;

            var name = file.name.toLowerCase();
            var isText = TEXT_EXTENSIONS.some(function (ext) { return name.endsWith(ext); });
            var isImage = IMAGE_EXTENSIONS.some(function (ext) { return name.endsWith(ext); });

            if (!isText && !isImage) {
                errorEl.textContent = "Unsupported file type. Accepted: .eml, .txt, or an "
                    + "email screenshot (.png/.jpg/.webp/.gif/.bmp).";
                errorEl.hidden = false;
                fileInput.value = "";
                return;
            }
            if (isText && file.size > MAX_TEXT_BYTES) {
                errorEl.textContent = "Text/.eml files are limited to 1 MB.";
                errorEl.hidden = false;
                fileInput.value = "";
                return;
            }
            if (isImage && file.size > MAX_IMAGE_BYTES) {
                errorEl.textContent = "Image screenshots are limited to 5 MB.";
                errorEl.hidden = false;
                fileInput.value = "";
            }
        });
    }

    document.addEventListener("DOMContentLoaded", function () {
        initSampleDropdown();
        initClearButton();
        initFileValidation();
    });
})();
