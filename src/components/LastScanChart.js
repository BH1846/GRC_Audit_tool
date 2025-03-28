import React from "react";
import { Bar } from "react-chartjs-2";
import { Box, useTheme } from "@mui/material";
import {
  Chart as ChartJS,
  BarElement,
  CategoryScale,
  LinearScale,
  Title,
  Tooltip,
  Legend,
} from "chart.js";

// Register chart components
ChartJS.register(BarElement, CategoryScale, LinearScale, Title, Tooltip, Legend);

const LastScanChart = () => {
  const theme = useTheme(); // Get theme for dark mode compatibility

  const data = {
    labels: ["High Risk", "Medium Risk", "Low Risk", "Passed"],
    datasets: [
      {
        label: "Last Scan Results",
        data: [3, 7, 10, 20], // Dummy data (Replace with real scan results)
        backgroundColor: ["#FF4C4C", "#FFA500", "#FFD700", "#4CAF50"],
        borderColor: ["#FF0000", "#FF8C00", "#DAA520", "#008000"],
        borderWidth: 1,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false, // Allows chart to take full width
    plugins: {
      legend: {
        position: "top",
        labels: {
          color: theme.palette.text.primary, // Ensure legend text matches dark mode
        },
      },
      title: {
        display: true,
        text: "Last Security Scan Summary",
        color: theme.palette.text.primary, // Title color in dark mode
      },
    },
    scales: {
      x: {
        ticks: { color: theme.palette.text.primary }, // Axis labels in dark mode
        grid: { color: theme.palette.divider }, // Grid color
      },
      y: {
        beginAtZero: true,
        ticks: { color: theme.palette.text.primary },
        grid: { color: theme.palette.divider },
      },
    },
  };

  return (
    <Box width="100%" height={400}>
      <Bar data={data} options={options} />
    </Box>
  );
};

export default LastScanChart;
