import React, { useState } from "react";
import {
  Button,
  Typography,
  LinearProgress,
  Card,
  CardContent,
  Alert,
  List,
  ListItem,
  ListItemText,
} from "@mui/material";
import axios from "axios";

const AuditChecks = () => {
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  const [detectedLogs, setDetectedLogs] = useState([]);
  const [auditSummary, setAuditSummary] = useState(null);
  const [loading, setLoading] = useState(false);

  const startAudit = async () => {
    setProgress(0);
    setLogs([]);
    setDetectedLogs([]);
    setAuditSummary(null);
    setLoading(true);

    try {
      const response = await axios.get("http://localhost:5000/run-audit");

      const { message, analysis_results } = response.data;

      let fakeLogs = [
        "Starting Audit...",
        "Collecting latest login logs...",
        "Generating JSON and PDF reports...",
        "Analyzing logs for suspicious activity...",
        message,
      ];

      let index = 0;
      const interval = setInterval(() => {
        if (index < fakeLogs.length) {
          setLogs((prevLogs) => [...prevLogs, fakeLogs[index]]);
          setProgress(((index + 1) / fakeLogs.length) * 100);
          index++;
        } else {
          clearInterval(interval);
          if (analysis_results) {
            setDetectedLogs(analysis_results.detected_logs || []);
            setAuditSummary(analysis_results.suspicious_count || {});
          }
          setLoading(false);
        }
      }, 1000);
    } catch (error) {
      console.error("Error running audit:", error);
      setLogs(["❌ Error: Unable to run audit. Check server connection."]);
      setLoading(false);
    }
  };

  return (
    <div>
      <Typography variant="h4" gutterBottom>
        Audit & Compliance Checks
      </Typography>
      <Button variant="contained" color="primary" onClick={startAudit} disabled={loading}>
        {loading ? "Running Audit..." : "Start Audit"}
      </Button>
      <LinearProgress variant="determinate" value={progress} style={{ marginTop: 20 }} />

      {/* Display real-time logs */}
      {logs.map((log, index) => (
        <Card key={index} style={{ marginTop: 10, backgroundColor: "#2e2e2e" }}>
          <CardContent>
            <Typography style={{ color: "#ddd" }}>{log}</Typography>
          </CardContent>
        </Card>
      ))}

      {/* Display detected suspicious logs */}
      {detectedLogs.length > 0 && (
        <div style={{ marginTop: 20 }}>
          <Typography variant="h5" gutterBottom>
            🚨 Detected Suspicious Logs:
          </Typography>
          <List style={{ backgroundColor: "#2e2e2e", padding: 10 }}>
            {detectedLogs.map((log, index) => (
              <ListItem key={index} divider>
                <ListItemText primary={log} style={{ color: "#ff5252" }} />
              </ListItem>
            ))}
          </List>
        </div>
      )}

      {/* Display audit summary */}
      {auditSummary && (
        <div style={{ marginTop: 20 }}>
          <Typography variant="h5" gutterBottom>
            ✅ Audit Summary:
          </Typography>
          {Object.keys(auditSummary).map((key, index) => (
            <Alert
              key={index}
              severity={auditSummary[key] > 0 ? "error" : "success"}
              style={{ marginBottom: 10 }}
            >
              {`${key}: ${auditSummary[key]} occurrence(s) found.`}
            </Alert>
          ))}
        </div>
      )}
    </div>
  );
};

export default AuditChecks;
