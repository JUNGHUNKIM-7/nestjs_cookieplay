import { PrismaClient } from "@prisma/client";

const p = new PrismaClient({ log: ["info", "error", "query"] });

async function main() {
  await p.$connect();
  await p.user.create({
    data: { email: "test@email.com", password: "testest" },
  });
}

main()
  .then(async () => {
    await p.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);

    await p.$disconnect();

    process.exit(1);
  });
