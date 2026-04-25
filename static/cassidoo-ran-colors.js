
let colors = ["#24d05a", "#eb4888", "#10a2f5", "#e9bc3f"];

function getRandomColor() {
    return colors[Math.floor(Math.random() * colors.length)];
}

function setRandomLinkColor() {
    Array.from(document.getElementsByTagName("a")).forEach((e) => {
        e.style.textDecorationColor = getRandomColor();
    });

    Array.from(document.getElementsByTagName("h2")).forEach((e) => {
        e.style.textDecorationColor = getRandomColor();
    });

    Array.from(document.getElementsByTagName("input")).forEach((e) => {
        e.style.borderBottomColor = getRandomColor();
    });
}

function setColorHoverListener() {
    Array.from(document.querySelectorAll("h2, a, button, input")).forEach((e) => {
        e.addEventListener("mouseover", setRandomLinkColor);
    });
}

(function () {
    setRandomLinkColor();
    setColorHoverListener();
})();

