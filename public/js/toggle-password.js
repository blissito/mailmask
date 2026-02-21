document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-toggle-password]");
  if (!btn) return;
  const input = btn.parentElement.querySelector("input");
  const isPassword = input.type === "password";
  input.type = isPassword ? "text" : "password";
  btn.querySelector(".eye-open").classList.toggle("hidden", !isPassword);
  btn.querySelector(".eye-closed").classList.toggle("hidden", isPassword);
});
