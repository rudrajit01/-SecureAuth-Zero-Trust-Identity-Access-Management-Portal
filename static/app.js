/**
 * SecureAuth - Enterprise Client Engine
 * Features:
 *   - Dark / Light Theme Manager (persisted to localStorage)
 *   - Password Strength Meter with NIST Guidance
 *   - Real-time PIM Expiry Countdown Timer
 *   - Drag-and-Drop File Upload Zone with File Preview
 *   - One-Click Demo Credentials Population
 *   - Instant Client-side Table Search / Filter
 *   - Copy to Clipboard Micro-interactions
 *   - Accessible Mobile Navigation Drawer
 */

document.addEventListener("DOMContentLoaded", function () {
  // -------------------------------------------------------------------------
  // 1. Theme Management (Dark / Light)
  // -------------------------------------------------------------------------
  var themeToggleBtn = document.getElementById("theme-toggle");
  var savedTheme = localStorage.getItem("secureauth_theme");
  var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  var currentTheme = savedTheme || (prefersDark ? "dark" : "light");

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("secureauth_theme", theme);
    if (themeToggleBtn) {
      themeToggleBtn.setAttribute("aria-label", "Switch to " + (theme === "dark" ? "light" : "dark") + " mode");
      themeToggleBtn.innerHTML = theme === "dark" ? "☀️ <span class='theme-txt'>Light</span>" : "🌙 <span class='theme-txt'>Dark</span>";
    }
  }

  applyTheme(currentTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", function () {
      var nextTheme = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      applyTheme(nextTheme);
    });
  }

  // -------------------------------------------------------------------------
  // 2. Mobile Navigation Toggle
  // -------------------------------------------------------------------------
  var mobileMenuBtn = document.getElementById("mobile-menu-btn");
  var sidebar = document.querySelector(".sidebar");
  var overlay = document.getElementById("sidebar-overlay");

  if (mobileMenuBtn && sidebar) {
    mobileMenuBtn.addEventListener("click", function () {
      sidebar.classList.toggle("open");
      if (overlay) overlay.classList.toggle("active");
    });
  }

  if (overlay && sidebar) {
    overlay.addEventListener("click", function () {
      sidebar.classList.remove("open");
      overlay.classList.remove("active");
    });
  }

  // -------------------------------------------------------------------------
  // 3. Password Strength Meter
  // -------------------------------------------------------------------------
  document.querySelectorAll("[data-strength]").forEach(function (input) {
    var bar = document.getElementById(input.dataset.strength);
    var txt = document.getElementById(input.dataset.strength + "-txt");
    input.addEventListener("input", function () {
      var p = input.value, s = 0;
      if (p.length >= 8) s++;
      if (p.length >= 12) s++;
      if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
      if (/\d/.test(p)) s++;
      if (/[^A-Za-z0-9]/.test(p)) s++;
      var levels = [
        ["0%", "#e5484d", ""],
        ["20%", "#e5484d", "Very weak"],
        ["40%", "#f97316", "Weak"],
        ["60%", "#eab308", "Fair"],
        ["80%", "#10b981", "Strong"],
        ["100%", "#059669", "Very strong"]
      ];
      var l = levels[p ? Math.max(s, 1) : 0];
      if (bar) {
        bar.style.width = l[0];
        bar.style.background = l[1];
      }
      if (txt) {
        txt.textContent = l[2];
        txt.style.color = l[1];
      }
    });
  });

  // -------------------------------------------------------------------------
  // 4. Confirm Dialogs for Sensitive Actions
  // -------------------------------------------------------------------------
  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (!confirm(f.dataset.confirm)) {
        e.preventDefault();
      }
    });
  });

  // -------------------------------------------------------------------------
  // 5. MFA Code Input (Digits Only & Auto-focus)
  // -------------------------------------------------------------------------
  document.querySelectorAll(".code-input").forEach(function (i) {
    i.addEventListener("input", function () {
      i.value = i.value.replace(/\D/g, "").slice(0, 6);
    });
  });

  // -------------------------------------------------------------------------
  // 6. Real-time Dynamic PIM Countdown Timer
  // -------------------------------------------------------------------------
  var pimTimerElem = document.getElementById("pim-timer");
  if (pimTimerElem && pimTimerElem.dataset.endtime) {
    var targetDate = new Date(pimTimerElem.dataset.endtime.replace(" ", "T")).getTime();

    function updatePimCountdown() {
      var now = Date.now();
      var diff = targetDate - now;

      if (diff <= 0) {
        pimTimerElem.innerHTML = "<span class='pulse-badge expired'>⏱️ Role Expired</span>";
        setTimeout(function () {
          window.location.reload();
        }, 2500);
        return;
      }

      var totalSec = Math.floor(diff / 1000);
      var hours = Math.floor(totalSec / 3600);
      var minutes = Math.floor((totalSec % 3600) / 60);
      var seconds = totalSec % 60;

      var formatted = "";
      if (hours > 0) formatted += hours + "h ";
      formatted += (minutes < 10 && hours > 0 ? "0" : "") + minutes + "m ";
      formatted += (seconds < 10 ? "0" : "") + seconds + "s remaining";

      pimTimerElem.textContent = formatted;
      if (minutes < 5 && hours === 0) {
        pimTimerElem.classList.add("timer-urgent");
      }
    }

    updatePimCountdown();
    setInterval(updatePimCountdown, 1000);
  }

  // -------------------------------------------------------------------------
  // 7. Click-to-Copy Utility
  // -------------------------------------------------------------------------
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.dataset.copy;
      if (!text) {
        var targetSel = btn.dataset.copyTarget;
        if (targetSel) {
          var targetElem = document.querySelector(targetSel);
          if (targetElem) text = targetElem.textContent.trim();
        }
      }
      if (text && navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function () {
          var original = btn.innerHTML;
          btn.innerHTML = "✓ Copied!";
          btn.classList.add("copied");
          setTimeout(function () {
            btn.innerHTML = original;
            btn.classList.remove("copied");
          }, 1800);
        });
      }
    });
  });

  // -------------------------------------------------------------------------
  // 8. Instant Client-Side Table Filter
  // -------------------------------------------------------------------------
  document.querySelectorAll("[data-table-filter]").forEach(function (input) {
    var tableSelector = input.dataset.tableFilter;
    var table = document.querySelector(tableSelector);
    if (!table) return;

    input.addEventListener("input", function () {
      var query = input.value.toLowerCase().trim();
      var rows = table.querySelectorAll("tbody tr, tr:not(:first-child)");
      var matchCount = 0;

      rows.forEach(function (row) {
        // Skip table headers and empty state rows
        if (row.querySelector("th") || row.classList.contains("empty-row")) return;
        var text = row.textContent.toLowerCase();
        var match = !query || text.indexOf(query) !== -1;
        row.style.display = match ? "" : "none";
        if (match) matchCount++;
      });

      var counter = document.getElementById(input.dataset.filterCounter);
      if (counter) {
        counter.textContent = query ? matchCount + " matching" : "";
      }
    });
  });

  // -------------------------------------------------------------------------
  // 9. DLP Drag-and-Drop Zone & Quick Samples
  // -------------------------------------------------------------------------
  var dropZone = document.getElementById("dlp-dropzone");
  var fileInput = document.getElementById("dlp-file-input");
  var fileInfo = document.getElementById("dlp-file-info");
  var dlpText = document.getElementById("dlp-text");

  if (dropZone && fileInput) {
    ["dragenter", "dragover"].forEach(function (evt) {
      dropZone.addEventListener(evt, function (e) {
        e.preventDefault();
        dropZone.classList.add("dragover");
      });
    });

    ["dragleave", "drop"].forEach(function (evt) {
      dropZone.addEventListener(evt, function (e) {
        e.preventDefault();
        dropZone.classList.remove("dragover");
      });
    });

    dropZone.addEventListener("drop", function (e) {
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        fileInput.files = e.dataTransfer.files;
        showSelectedFileInfo(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener("change", function () {
      if (fileInput.files && fileInput.files.length > 0) {
        showSelectedFileInfo(fileInput.files[0]);
      }
    });

    function showSelectedFileInfo(file) {
      if (fileInfo) {
        var sizeKb = (file.size / 1024).toFixed(1);
        fileInfo.innerHTML = "📄 <strong>" + file.name + "</strong> (" + sizeKb + " KB) ready for inspection";
        fileInfo.style.display = "block";
      }
    }
  }

  // Quick DLP Demo Samples
  document.querySelectorAll("[data-dlp-sample]").forEach(function (chip) {
    chip.addEventListener("click", function () {
      if (!dlpText) return;
      var type = chip.dataset.dlpSample;
      if (type === "aadhaar") {
        dlpText.value =
          "Customer KYC Record:\nName: Rajesh Kumar\nAadhaar: 2345 6789 0124\nPAN: ABCPS1234K\nCard: 4111 1111 1111 1111\nMobile: +91 9876543210\nBank IFSC: SBIN0001234\nNotes: Urgent KYC renewal.";
      } else if (type === "internal") {
        dlpText.value =
          "Internal Team Meeting Notes:\nDate: 18 Nov 2026\nCoordinator: team.lead@secureauth.local\nMobile: 9988776655\nAgenda: Security audit review, quarterly access certification.";
      } else if (type === "clean") {
        dlpText.value =
          "Public Notice:\nOffice hours are from 9:00 AM to 6:00 PM Monday through Friday.\nPlease consult the official handbook for company holidays.";
      } else if (type === "clear") {
        dlpText.value = "";
      }
      dlpText.focus();
    });
  });
});

// ---------------------------------------------------------------------------
// 10. Global Demo Credentials Quick Filler
// ---------------------------------------------------------------------------
window.fillDemo = function (username, password) {
  var u = document.getElementById("username");
  var p = document.getElementById("password");
  if (u && p) {
    u.value = username;
    p.value = password;
    u.classList.add("input-pulse");
    p.classList.add("input-pulse");
    setTimeout(function () {
      u.classList.remove("input-pulse");
      p.classList.remove("input-pulse");
    }, 600);
    p.focus();
  }
};
