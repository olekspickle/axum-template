document.addEventListener("DOMContentLoaded", () => {
    const target = document.getElementById("currentYear");
    if (target) target.textContent = new Date().getFullYear();
});
