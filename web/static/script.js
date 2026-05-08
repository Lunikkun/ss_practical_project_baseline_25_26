document.addEventListener("DOMContentLoaded", () => {

  const params = new URLSearchParams(window.location.search);
  const title = params.get("uploaded");

  if (title)
  {
      const container = document.getElementById("flash-container");
      if (container)
      {
          const li = document.createElement("li");
          li.className = "flash success";

          li.innerHTML = `Document uploaded: ${title}`;

          container.appendChild(li);
      }
  }

  const buttons = document.querySelectorAll(".details-btn");

  buttons.forEach(btn => {
    btn.addEventListener("click", () => {
      const title = btn.dataset.title || "";

      let details = document.getElementById("doc-details");
      let titleField = document.getElementById("doc-title");

      if (!details || !titleField) {
        details = document.createElement("div");
        details.id = "doc-details";
        details.className = "card";

        const heading = document.createElement("h3");
        heading.textContent = "Document details";
        titleField = document.createElement("p");
        titleField.id = "doc-title";

        details.appendChild(heading);
        details.appendChild(titleField);

        const parentCard = btn.closest(".card");
        if (parentCard) {
          parentCard.appendChild(details);
        }
      }

      details.style.display = "block";
      renderTitle(title);
    });
  });

    function renderTitle(title) {
      const el = document.getElementById("doc-title");
      updateField(el, title);
    }

    function updateField(element, value) {
      if (!element) return;
      element.textContent = "Title: " + value;
    }

});