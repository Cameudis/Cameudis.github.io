(() => {
  const notes = Array.from(document.querySelectorAll(".hover-note"));
  if (!notes.length) return;

  const viewportMargin = 12;
  const gap = 10;
  let activeNote = null;

  const clamp = (value, minimum, maximum) =>
    Math.min(Math.max(value, minimum), maximum);

  const positionNote = (note) => {
    const story = note.querySelector(".hover-note__story");
    if (!story) return;

    const anchorRect = note.getBoundingClientRect();
    const storyRect = story.getBoundingClientRect();
    const halfWidth = storyRect.width / 2;
    const center = clamp(
      anchorRect.left + anchorRect.width / 2,
      viewportMargin + halfWidth,
      window.innerWidth - viewportMargin - halfWidth
    );
    const fitsAbove = anchorRect.top >= storyRect.height + gap + viewportMargin;
    const placement = fitsAbove ? "top" : "bottom";
    const y = fitsAbove ? anchorRect.top - gap : anchorRect.bottom + gap;

    note.dataset.hoverNotePlacement = placement;
    note.style.setProperty("--hover-note-x", `${center}px`);
    note.style.setProperty("--hover-note-y", `${y}px`);
  };

  const activate = (note) => {
    activeNote = note;
    positionNote(note);
  };

  notes.forEach((note) => {
    note.addEventListener("pointerenter", () => activate(note));
    note.addEventListener("focus", () => activate(note));
    note.addEventListener("pointerleave", () => {
      if (activeNote === note && document.activeElement !== note) activeNote = null;
    });
    note.addEventListener("blur", () => {
      if (activeNote === note && !note.matches(":hover")) activeNote = null;
    });
  });

  const repositionActiveNote = () => {
    if (activeNote) positionNote(activeNote);
  };

  window.addEventListener("resize", repositionActiveNote);
  window.addEventListener("scroll", repositionActiveNote, { passive: true });
  document.documentElement.classList.add("has-hover-notes");
})();
