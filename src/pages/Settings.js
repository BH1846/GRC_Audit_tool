import React from "react";
import { Typography, Switch, FormControlLabel } from "@mui/material";

const Settings = () => {
  return (
    <div>
      <Typography variant="h4" gutterBottom>Settings</Typography>
      <FormControlLabel control={<Switch />} label="Enable Auto-Scan" />
      <FormControlLabel control={<Switch />} label="Enable Dark Mode" />
    </div>
  );
};

export default Settings;
