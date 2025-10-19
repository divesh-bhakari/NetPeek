const fileInput = document.getElementById('fileInput');
const uploadBtn = document.getElementById('uploadBtn');
const progressContainer = document.getElementById('progressContainer');
const progressBar = document.getElementById('progressBar');
const progressText = document.getElementById('progressText');
const resultMessage = document.getElementById('resultMessage');

uploadBtn.addEventListener('click', () => {
  const file = fileInput.files[0];
  if (!file) {
    alert("Please select a file first!");
    return;
  }

  const formData = new FormData();
  formData.append("file", file);

  progressContainer.style.display = "block";
  progressBar.style.width = "0%";
  progressText.innerText = "0%";
  resultMessage.innerText = "";

  fetch("http://127.0.0.1:5000/upload", {
    method: "POST",
    body: formData
  }).then(async response => {
    const data = await response.json();
    if (response.ok) {
      resultMessage.innerHTML = `✅ ${data.message}<br>Total Packets Parsed: ${data.summary.packets_parsed}`;
    } else {
      resultMessage.innerHTML = `❌ Error: ${data.error}`;
    }
    progressBar.style.width = "100%";
    progressText.innerText = "100%";
  }).catch(err => {
    resultMessage.innerHTML = `❌ Error: ${err}`;
    progressBar.style.width = "100%";
    progressText.innerText = "100%";
  });
});
