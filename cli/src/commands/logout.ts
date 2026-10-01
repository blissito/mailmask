import { defineCommand } from "citty";
import { clearCredentials, credentialsFilePath } from "../config.js";

export default defineCommand({
  meta: {
    name: "logout",
    description: "Olvida la API key guardada (keychain del SO y/o archivo local); no la revoca en MailMask",
  },
  async run() {
    const removed = await clearCredentials();
    if (process.env.MAILMASK_API_KEY) {
      process.stdout.write(
        "MAILMASK_API_KEY sigue fijada en tu entorno: mientras exista, los comandos la van a seguir usando.\n",
      );
    }
    if (removed) {
      process.stdout.write(`✓ Sesión borrada (keychain y/o ${credentialsFilePath()})\n`);
    } else {
      process.stdout.write("No había ninguna sesión guardada.\n");
    }
  },
});
