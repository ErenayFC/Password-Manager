import inquirer from "inquirer";
import fs from "fs";
import crypto from "crypto";
import chalk from "chalk";
import figlet from "figlet";

function clear() {
  process.stdout.write('\x1Bc');
}

function exitHandler() {
  console.log(chalk.yellow("\nProgramdan çıkılıyor... İyi günler!"));
  process.exit();
}

process.on('SIGINT', exitHandler);

const PASSWORDS_FILE = "passwords.dat";
const ENCRYPT_KEY_FILE = "encrypt_key.dat";

function generateAndStoreEncryptKey(key) {
  const salt = crypto.randomBytes(16);
  const encryptKey = crypto.pbkdf2Sync(key, salt, 100000, 32, "sha512");
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptKey, iv);
  let encrypted = cipher.update(key, "utf8");
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();

  const dataToStore = Buffer.concat([
    salt,
    iv,
    authTag,
    Buffer.from([encrypted.length]),
    encrypted,
  ]);

  fs.writeFileSync(ENCRYPT_KEY_FILE, dataToStore);
  return encryptKey;
}

function getEncryptKey(key) {
  const storedData = fs.readFileSync(ENCRYPT_KEY_FILE);
  const salt = storedData.slice(0, 16);
  const iv = storedData.slice(16, 32);
  const authTag = storedData.slice(32, 48);
  const encryptedLength = storedData[48];
  const encrypted = storedData.slice(49, 49 + encryptedLength);

  const encryptKey = crypto.pbkdf2Sync(key, salt, 100000, 32, "sha512");
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptKey, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return crypto.pbkdf2Sync(
    decrypted.toString("utf8"),
    salt,
    100000,
    32,
    "sha512"
  );
}

let encryptKey;
let passwords = {};

function loadPasswords() {
  if (fs.existsSync(PASSWORDS_FILE)) {
    const data = fs.readFileSync(PASSWORDS_FILE);
    let offset = 0;
    while (offset < data.length) {
      const nameLength = data.readUInt8(offset);
      offset += 1;
      const name = data.slice(offset, offset + nameLength).toString('utf8');
      offset += nameLength;
      
      const ivLength = data.readUInt8(offset);
      offset += 1;
      const iv = data.slice(offset, offset + ivLength);
      offset += ivLength;
      
      const authTagLength = data.readUInt8(offset);
      offset += 1;
      const authTag = data.slice(offset, offset + authTagLength);
      offset += authTagLength;
      
      const encryptedDataLength = data.readUInt16BE(offset);
      offset += 2;
      const encryptedData = data.slice(offset, offset + encryptedDataLength).toString('hex');
      offset += encryptedDataLength;
      
      passwords[name] = {
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        encryptedData: encryptedData
      };
    }
  }
}

function savePasswords() {
  let data = Buffer.alloc(0);
  for (const [name, password] of Object.entries(passwords)) {
    const nameBuffer = Buffer.from(name, 'utf8');
    const ivBuffer = Buffer.from(password.iv, 'hex');
    const authTagBuffer = Buffer.from(password.authTag, 'hex');
    const encryptedDataBuffer = Buffer.from(password.encryptedData, 'hex');
    
    data = Buffer.concat([
      data,
      Buffer.from([nameBuffer.length]),
      nameBuffer,
      Buffer.from([ivBuffer.length]),
      ivBuffer,
      Buffer.from([authTagBuffer.length]),
      authTagBuffer,
      Buffer.alloc(2),
      encryptedDataBuffer
    ]);
    data.writeUInt16BE(encryptedDataBuffer.length, data.length - encryptedDataBuffer.length - 2);
  }
  fs.writeFileSync(PASSWORDS_FILE, data);
}

async function initializeEncryptKey() {
  if (!fs.existsSync(ENCRYPT_KEY_FILE)) {
    const { key } = await inquirer.prompt({
      type: "password",
      name: "key",
      message: "Lütfen yeni bir şifreleme anahtarı girin:",
      mask: "*",
    });
    const { confirmKey } = await inquirer.prompt({
      type: "password",
      name: "confirmKey",
      message: "Lütfen şifreleme anahtarını tekrar girin:",
      mask: "*",
    });
    if (key !== confirmKey) {
      console.log(
        chalk.red("Şifreleme anahtarları eşleşmiyor. Lütfen tekrar deneyin.")
      );
      return initializeEncryptKey();
    }
    const { confirm } = await inquirer.prompt({
      type: "confirm",
      name: "confirm",
      message: "Şifreleme anahtarını onaylıyor musunuz?",
    });
    if (!confirm) {
      return initializeEncryptKey();
    }
    encryptKey = generateAndStoreEncryptKey(key);
  } else {
    const { key } = await inquirer.prompt({
      type: "password",
      name: "key",
      message: "Lütfen mevcut şifreleme anahtarınızı girin:",
      mask: "*",
    });
    try {
      encryptKey = getEncryptKey(key);
    } catch (error) {
      console.log(
        chalk.red("Yanlış şifreleme anahtarı. Lütfen tekrar deneyin.")
      );
      return initializeEncryptKey();
    }
  }

  loadPasswords();
}

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptKey, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString("hex"),
    encryptedData: encrypted,
    authTag: authTag.toString("hex"),
  };
}

function decrypt(encryptedObj) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    encryptKey,
    Buffer.from(encryptedObj.iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(encryptedObj.authTag, "hex"));
  let decrypted = decipher.update(encryptedObj.encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function displayBanner() {
  clear();
  console.log(
    chalk.yellow(
      figlet.textSync("Şifre Yöneticisi", { horizontalLayout: "full" })
    )
  );
}

async function main() {
  await initializeEncryptKey();
  const initialQuestion = {
    type: "list",
    name: "action",
    message: "Ne yapmak istersiniz?",
    choices: [
      { name: chalk.green("Şifreleri Görüntüle"), value: "Görüntüle" },
      { name: chalk.blue("Yeni Şifre Oluştur"), value: "Oluştur" },
      { name: chalk.red("Şifre Sil"), value: "Sil" },
      { name: chalk.gray("Çıkış"), value: "Çıkış" },
    ],
  };

  while (true) {
    displayBanner();
    console.log(chalk.cyan("Hoş geldiniz! Lütfen bir işlem seçin.\n"));

    const { action } = await inquirer.prompt(initialQuestion);

    switch (action) {
      case "Görüntüle":
        await handleView();
        break;
      case "Oluştur":
        await handleCreate();
        break;
      case "Sil":
        await handleDelete();
        break;
      case "Çıkış":
        exitHandler();
        return;
    }

    console.log(chalk.dim("\nDevam etmek için bir tuşa basın..."));
    await inquirer.prompt({ type: "input", name: "continue", message: "" });
  }
}

async function handleView() {
  clear();
  displayBanner();
  console.log(chalk.cyan("Kaydedilmiş Şifreler:\n"));

  if (Object.keys(passwords).length === 0) {
    console.log(chalk.yellow("Henüz kaydedilmiş şifre bulunmamaktadır."));
    return;
  }
  for (let [applicationName, encryptedPassword] of Object.entries(passwords)) {
    try {
      const decryptedPassword = decrypt(encryptedPassword);
      console.log(
        chalk.green(`${applicationName}:`),
        chalk.white(decryptedPassword)
      );
    } catch (error) {
      console.log(chalk.red(`${applicationName}: Şifre çözülemedi`));
    }
  }
}

async function handleCreate() {
  clear();
  displayBanner();
  console.log(chalk.cyan("Yeni Şifre Oluştur:\n"));

  const questions = [
    {
      type: "input",
      name: "applicationName",
      message: "Uygulama adı nedir?",
      default: "uygulama-ismi",
    },
    {
      type: "password",
      name: "password",
      message: "Şifre nedir?",
      mask: "*",
    },
  ];

  const answers = await inquirer.prompt(questions);
  passwords[answers.applicationName] = encrypt(answers.password);
  savePasswords();
  console.log(
    chalk.green(
      `\n"${answers.applicationName}" için şifre başarıyla kaydedildi.`
    )
  );
}

async function handleDelete() {
  clear();
  displayBanner();
  console.log(chalk.cyan("Şifre Sil:\n"));

  if (Object.keys(passwords).length === 0) {
    console.log(chalk.yellow("Silinecek şifre bulunmamaktadır."));
    return;
  }

  const question = {
    type: "list",
    name: "projectToDelete",
    message: "Hangi projenin şifresini silmek istersiniz?",
    choices: Object.keys(passwords),
  };

  const { projectToDelete } = await inquirer.prompt(question);
  delete passwords[projectToDelete];
  savePasswords();
  console.log(
    chalk.green(`\n"${projectToDelete}" için şifre başarıyla silindi.`)
  );
}

main().catch((error) => {
  console.error(chalk.red('Bir hata oluştu'));
  exitHandler();
});