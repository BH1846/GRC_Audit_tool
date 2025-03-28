import React from "react";
import { Card, CardContent, Typography, Grid, LinearProgress, Container, Box } from "@mui/material";
import LastScanChart from "../components/LastScanChart"; // Import Chart Component

const Dashboard = () => {
  const complianceData = [
    { name: "GDPR", percentage: 85 },
    { name: "ISO 27001", percentage: 70 },
    { name: "HIPAA", percentage: 90 },
  ];

  return (
    <Container maxWidth="lg">
      <Typography variant="h4" gutterBottom color="text.primary">
        Dashboard
      </Typography>

      {/* Compliance Status Cards */}
      <Grid container spacing={2}>
        {complianceData.map((item) => (
          <Grid item xs={12} sm={4} key={item.name}>
            <Card sx={{ backgroundColor: "background.paper", color: "text.primary" }}>
              <CardContent>
                <Typography variant="h6">{item.name}</Typography>
                <LinearProgress variant="determinate" value={item.percentage} color="primary" />
                <Typography>{item.percentage}% Compliance</Typography>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Full-Width Last Scan Chart */}
      <Box mt={4}>
        <Card sx={{ backgroundColor: "background.paper", color: "text.primary" }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Last Scan Summary
            </Typography>
            <LastScanChart />
          </CardContent>
        </Card>
      </Box>
    </Container>
  );
};

export default Dashboard;
