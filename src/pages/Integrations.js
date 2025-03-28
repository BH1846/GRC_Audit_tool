import React from "react";
import { Typography, Card, CardContent } from "@mui/material";

const Integrations = () => {
  return (
    <div>
      <Typography variant="h4" gutterBottom>Integrations & APIs</Typography>
      <Card>
        <CardContent>
          <Typography variant="h6">SIEM Integration</Typography>
          <Typography>Connected to Splunk</Typography>
        </CardContent>
      </Card>
    </div>
  );
};

export default Integrations;
