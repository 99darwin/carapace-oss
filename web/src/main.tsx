import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ApiClient } from "./api";
import { App } from "./App";
import "./styles.css";

const root = document.getElementById("root");
if (root === null) throw new Error("missing #root element");

createRoot(root).render(
  <StrictMode>
    <App client={new ApiClient()} />
  </StrictMode>,
);
