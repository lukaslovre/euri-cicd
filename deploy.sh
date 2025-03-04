#!/bin/bash

# Define project directory
PROJECT_DIR="/home/ubuntu/euri"
LOG_FILE="$(dirname "$0")/deploy.log"
PM2_APP_NAME="app"

# Change to project directory
cd "$PROJECT_DIR" || { echo "Failed to navigate to project directory."; exit 1; }

# Log deployment start time
echo "Deployment started at $(date)" >> "$LOG_FILE"

# Pull the latest changes from GitHub
echo "Pulling latest changes from repository..."
git pull origin main >> "$LOG_FILE" 2>&1 || { echo "Git pull failed."; exit 1; }

# Install dependencies
echo "Installing dependencies..."
npm install >> "$LOG_FILE" 2>&1 || { echo "npm install failed."; exit 1; }

# Build the backend TypeScript
echo "Building backend TypeScript..."
npm run build >> "$LOG_FILE" 2>&1 # || { echo "Backend build failed."; exit 1; }

# Build the frontend TypeScript
echo "Building frontend TypeScript..."
npm run build-client >> "$LOG_FILE" 2>&1 # || { echo "Frontend build failed."; exit 1; }

# Copy EJS views from src to dist
echo "Copying EJS views..."
npm run copy-ejs >> "$LOG_FILE" 2>&1 || { echo "Copying EJS views failed."; exit 1; }

# Restart the application (if using PM2 or another process manager)
echo "Restarting application..."
pm2 restart "$PM2_APP_NAME" >> "$LOG_FILE" 2>&1 || { echo "PM2 restart failed."; exit 1; }

# Log deployment completion
echo "Deployment finished at $(date)" >> "$LOG_FILE"
echo "Deployment successful!"
