import React, { useState } from "react";
import { Drawer, IconButton, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Divider, Typography, Box } from "@mui/material";
import MenuIcon from "@mui/icons-material/Menu";
import DashboardIcon from "@mui/icons-material/Dashboard";
import SecurityIcon from "@mui/icons-material/Security";
import AssessmentIcon from "@mui/icons-material/Assessment";
import DescriptionIcon from "@mui/icons-material/Description";
import SettingsIcon from "@mui/icons-material/Settings";
import { Link } from "react-router-dom";

const Sidebar = () => {
  const [open, setOpen] = useState(true); // Sidebar state

  const toggleSidebar = () => {
    setOpen(!open);
  };

  return (
    <Drawer
      variant="permanent"
      sx={{
        width: open ? 240 : 70,
        flexShrink: 0,
        "& .MuiDrawer-paper": {
          width: open ? 240 : 70,
          transition: "width 0.3s ease-in-out",
          backgroundColor: "#121212",
          color: "#fff",
          overflowX: "hidden",
        },
      }}
    >
      {/* Top Section with Hamburger Menu and "ReconX" */}
      <Box display="flex" alignItems="center" p={2}>
        <IconButton onClick={toggleSidebar} sx={{ color: "white" }}>
          <MenuIcon />
        </IconButton>
        {open && (
          <Typography variant="h6" sx={{ marginLeft: 1 }}>
            ReconX
          </Typography>
        )}
      </Box>

      <Divider />

      {/* Sidebar Items */}
      <List>
        {[
          { text: "Dashboard", icon: <DashboardIcon />, path: "/" },
          { text: "Audit & Compliance", icon: <SecurityIcon />, path: "/audit-checks" },
          { text: "Risk Assessment", icon: <AssessmentIcon />, path: "/risk-assessment" },
          { text: "Reports", icon: <DescriptionIcon />, path: "/reports" },
          { text: "Settings", icon: <SettingsIcon />, path: "/settings" },
        ].map((item) => (
          <ListItem key={item.text} disablePadding>
            <ListItemButton component={Link} to={item.path}>
              <ListItemIcon sx={{ color: "white" }}>{item.icon}</ListItemIcon>
              {open && <ListItemText primary={item.text} />}
            </ListItemButton>
          </ListItem>
        ))}
      </List>
    </Drawer>
  );
};

export default Sidebar;
