import React, { useEffect, useState } from "react";
import { Card, CardContent, Typography, Button } from "@mui/material";

const Reports = () => {
  const [reportDate, setReportDate] = useState("");
  const [auditMessage, setAuditMessage] = useState("");

  useEffect(() => {
    fetch("http://localhost:5000/get-audit-results")
      .then((res) => res.json())
      .then((data) => {
        if (data.message) {
          setAuditMessage(data.message);
        }
        if (data.date) {
          setReportDate(data.date);
        }
      })
      .catch((error) => console.error("Error fetching audit results:", error));
  }, []);

  const downloadReport = () => {
    window.open("http://localhost:5000/download-report", "_blank");
  };

  return (
    <div>
      <Typography variant="h4" gutterBottom>
        Audit Reports
      </Typography>

      <Card style={{ marginBottom: 20 }}>
        <CardContent>
          <Typography variant="h6">Recent Audit Report</Typography>
          <Typography>Date: {reportDate || "N/A"}</Typography>
          <Button variant="contained" color="primary" onClick={downloadReport} style={{ marginTop: 10 }}>
            Download Report
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            {auditMessage}
          </Typography>
        </CardContent>
      </Card>
    </div>
  );
};

export default Reports;
