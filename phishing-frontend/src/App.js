import React, { useState } from "react";
import "./App.css";

function App() {
  const [url, updateUrl] = useState("");
  const [res, updateRes] = useState("No URL checked yet");

  const checkButton = () => {
    if (url.trim() === "") {
      updateRes("Please enter a URL");
      return;
    }
    updateRes("Checking...");
  };
  return (
    <div className="app">
      <div className="card">
        <h1 className="title">Phishing URL Detector</h1>
        <p className="subtitle">
          Enter a URL below to analyze whether it looks safe, suspicious, or phishing.
        </p>

        <label className="input-label">Enter URL</label>
        <input
          type="text"
          placeholder="https://example.com"
          value={url}
          onChange={(e) => updateUrl(e.target.value)}
          className="url-input"
        />

        <button className="check-btn" onClick={checkButton}>
          Check URL
        </button>

        <div className="result-box">
          <h3>Result</h3>
          <p>{res}</p>
        </div>
      </div>
    </div>
  );
}

export default App;