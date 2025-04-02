// index.ts - CLI entry point
import * as readline from 'readline';
import { collectAllGeckoData } from './GeckoDecryptor';

// Create readline interface
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

async function main() {
  console.log('======================================');
  console.log('Gecko Browser Data Decryptor');
  console.log('======================================');
  console.log('This tool extracts and decrypts data from Gecko-based browsers');
  console.log('(Firefox, Thunderbird, etc.) including passwords, cookies,');
  console.log('bookmarks, and browsing history.');
  console.log('======================================');
  
  // Get username
  const username = await new Promise<string>((resolve) => {
    rl.question('Enter Windows username: ', (answer) => {
      resolve(answer);
    });
  });
  
  // Get output path
  const outputPath = await new Promise<string>((resolve) => {
    rl.question('Enter output directory (default: ./output): ', (answer) => {
      resolve(answer || './output');
    });
  });
  
  rl.close();
  
  console.log(`\nStarting data collection for user: ${username}`);
  console.log(`Output will be saved to: ${outputPath}\n`);
  
  try {
    await collectAllGeckoData(username, outputPath);
    console.log('\nData collection complete. Check the output directory for JSON files.');
  } catch (error) {
    console.error('An error occurred during data collection:', error);
  }
}

// Run the main function
main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
