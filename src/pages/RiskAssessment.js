import React from "react";
import { Card, CardContent, Typography, Grid } from "@mui/material";

const RiskAssessment = () => {
  const risks = [
    { id: 1, category: "High", description: "Unauthorized access detected" },
    { id: 2, category: "Medium", description: "Outdated software found" },
    { id: 3, category: "Low", description: "Weak password policy" },
  ];

  return (
    <div>
      <Typography variant="h4" gutterBottom>Risk Assessment</Typography>
      <Grid container spacing={2}>
        {risks.map((risk) => (
          <Grid item xs={12} key={risk.id}>
            <Card>
              <CardContent>
                <Typography variant="h6">{risk.category} Risk</Typography>
                <Typography>{risk.description}</Typography>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </div>
  );
};

export default RiskAssessment;
