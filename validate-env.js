#!/usr/bin/env node

/**
 * Environment Variables Validation Script
 * 
 * This script validates that all required environment variables are set
 * and provides helpful error messages if any are missing.
 */

require('dotenv').config();

const requiredEnvVars = [
  'SPOTIFY_CLIENT_ID',
  'SPOTIFY_CLIENT_SECRET', 
  'SPOTIFY_PLAYLIST_ID',
  'SUPABASE_URL',
  'SUPABASE_ANON_KEY'
];

const optionalEnvVars = [
  'SPOTIFY_REDIRECT_URI',
  'ADMIN_PASSWORD',
  'SPOTIFY_AUTH_PASSWORD',
  'PORT'
];

function validateEnvironment() {
  console.log('🔍 Validating environment variables...\n');
  
  let hasErrors = false;
  const missing = [];
  const present = [];
  
  // Check required variables
  requiredEnvVars.forEach(varName => {
    if (!process.env[varName]) {
      missing.push(varName);
      hasErrors = true;
    } else {
      present.push(varName);
    }
  });
  
  // Check optional variables
  const optionalPresent = [];
  const optionalMissing = [];
  
  optionalEnvVars.forEach(varName => {
    if (process.env[varName]) {
      optionalPresent.push(varName);
    } else {
      optionalMissing.push(varName);
    }
  });
  
  // Report results
  if (present.length > 0) {
    console.log('✅ Required variables present:');
    present.forEach(varName => {
      const value = process.env[varName];
      const displayValue = varName.includes('SECRET') || varName.includes('PASSWORD') || varName.includes('KEY')
        ? '***' + value.slice(-4)
        : value;
      console.log(`   ${varName}: ${displayValue}`);
    });
    console.log();
  }
  
  if (optionalPresent.length > 0) {
    console.log('✅ Optional variables present:');
    optionalPresent.forEach(varName => {
      const value = process.env[varName];
      const displayValue = varName.includes('SECRET') || varName.includes('PASSWORD') || varName.includes('KEY')
        ? '***' + value.slice(-4)
        : value;
      console.log(`   ${varName}: ${displayValue}`);
    });
    console.log();
  }
  
  if (missing.length > 0) {
    console.log('❌ Missing required variables:');
    missing.forEach(varName => {
      console.log(`   ${varName}`);
    });
    console.log();
  }
  
  if (optionalMissing.length > 0) {
    console.log('⚠️  Missing optional variables (will use defaults):');
    optionalMissing.forEach(varName => {
      console.log(`   ${varName}`);
    });
    console.log();
  }
  
  if (hasErrors) {
    console.log('❌ Environment validation failed!');
    console.log('Please set the missing required variables and try again.');
    console.log('See .env.example for reference.');
    process.exit(1);
  } else {
    console.log('✅ Environment validation passed!');
    console.log('All required variables are set.');
  }
}

if (require.main === module) {
  validateEnvironment();
}

module.exports = { validateEnvironment };
