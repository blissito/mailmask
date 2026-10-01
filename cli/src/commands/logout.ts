import { defineCommand } from "citty";
import { clearCredentials, credentialsFilePath } from "../config.js";

export default defineCommand({
  meta: {
    name: "logout",
    description: "Olvida la API key guardada localmente (no la revoca en MailMask)",
  },
  async run() {
    const removed = clearCredentials();
    if (process.env.MAILMASK_API_KEY) {
      process.stdout.write(
        "MAILMASK_API_KEY sigue fijada en tu entorno: mientras exista, los comandos la van a seguir usando.\n",
      );
    }
    if (removed) {
      process.stdout.write(`✓ Se borró ${credentialsFilePath()}\n`);
    } else {
      process.stdout.write("No había ninguna sesión guardada.\n");
    }
  },
});
