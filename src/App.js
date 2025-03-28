import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { ThemeProvider, createTheme, CssBaseline, Container } from "@mui/material";
import Sidebar from "./components/SideBar";
import Dashboard from "./pages/Dashboard";
import AuditChecks from "./pages/AuditChecks";
import RiskAssessment from "./pages/RiskAssessment";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";


// Create a dark theme
const darkTheme = createTheme({
  palette: {
    mode: "dark",
    background: {
      default: "#121212",
      paper: "#1e1e1e",
    },
    text: {
      primary: "#ffffff",
      secondary: "#aaaaaa",
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline /> {/* Ensures dark background is applied */}
      <Router>
        <div style={{ display: "flex" }}>
          <Sidebar />
          <Container style={{padding: 20, flexGrow: 1 }}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/audit-checks" element={<AuditChecks />} />
              <Route path="/risk-assessment" element={<RiskAssessment />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </Container>
        </div>
      </Router>
    </ThemeProvider>
  );
}

export default App;
