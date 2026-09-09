(() => {
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function setActive(shot, id) {
    shot.querySelectorAll("[data-tip-id]").forEach((el) => {
      const on = el.getAttribute("data-tip-id") === id;
      el.classList.toggle("is-active", on);
      if (el.tagName === "BUTTON" && el.classList.contains("hotspot")) {
        el.setAttribute("aria-pressed", on ? "true" : "false");
      }
    });
    const panel = shot.querySelector(".tip-panel");
    const tip = shot.querySelector(`.tip-copy[data-tip-id="${id}"]`);
    if (panel && tip) {
      panel.innerHTML = tip.innerHTML;
      panel.dataset.active = id;
    }
  }

  function stopTour(shot) {
    if (shot._tourTimer) {
      clearInterval(shot._tourTimer);
      shot._tourTimer = null;
    }
    if (shot._tourEnd) {
      clearTimeout(shot._tourEnd);
      shot._tourEnd = null;
    }
    const btn = shot.querySelector("[data-tour]");
    if (btn) {
      btn.textContent = "Play tip tour";
      btn.setAttribute("aria-pressed", "false");
    }
  }

  function startTour(shot) {
    const ids = [...shot.querySelectorAll(".tip-copy")].map((n) => n.getAttribute("data-tip-id"));
    if (!ids.length) return;
    stopTour(shot);
    let i = 0;
    setActive(shot, ids[0]);
    const btn = shot.querySelector("[data-tour]");
    if (btn) {
      btn.textContent = "Stop tour";
      btn.setAttribute("aria-pressed", "true");
    }
    if (reduce) return;
    shot._tourTimer = setInterval(() => {
      i = (i + 1) % ids.length;
      setActive(shot, ids[i]);
      if (i === ids.length - 1) {
        // end after one full loop + brief pause handled by next tick stop
      }
    }, 2200);
    // auto-stop after one full pass
    const total = ids.length * 2200;
    shot._tourEnd = setTimeout(() => stopTour(shot), total + 200);
  }

  document.querySelectorAll(".shot[data-interactive]").forEach((shot) => {
    const first = shot.querySelector(".tip-copy");
    if (first) setActive(shot, first.getAttribute("data-tip-id"));

    shot.addEventListener("click", (e) => {
      const tour = e.target.closest("[data-tour]");
      if (tour && shot.contains(tour)) {
        if (shot._tourTimer) stopTour(shot);
        else startTour(shot);
        return;
      }
      const hit = e.target.closest("[data-tip-id]");
      if (!hit || !shot.contains(hit)) return;
      stopTour(shot);
      setActive(shot, hit.getAttribute("data-tip-id"));
    });
  });
})();
