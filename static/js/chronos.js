(() => {
    // Recovered incident reference:
    // The corresponding manifest describes the damaged archive.
    const incidentManifest = "/archive-maint/CHR-05/manifest.json";
    const button = document.getElementById("archive-control");
    const message = document.getElementById("interaction-message");

    if (!button || !message) {
        return;
    }

    const positions = [
        [-45, 18],
        [55, -12],
        [-20, -24],
        [38, 14],
        [-60, -8],
        [12, 25]
    ];

    let moveCount = 0;

    function displaceControl() {
        const [x, y] = positions[moveCount % positions.length];
        moveCount++;

        button.style.setProperty("--shift-x", `${x}px`);
        button.style.setProperty("--shift-y", `${y}px`);

        message.textContent =
            "TEMPORAL DISPLACEMENT DETECTED // CHR-05";
    }

    button.addEventListener("pointerdown", (event) => {
        event.preventDefault();
        displaceControl();
    });

    // Support keyboard activation as well.
    button.addEventListener("click", (event) => {
        event.preventDefault();

        if (event.detail === 0) {
            displaceControl();
        }
    });
})();
