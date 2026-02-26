import { Command } from "commander";
import { initCommand } from "./commands/init.js";
import { keygenCommand } from "./commands/keygen.js";
import { signCommand } from "./commands/sign.js";
import { verifyCommand } from "./commands/verify.js";
import { verifyConstitutionCommand } from "./commands/verify-constitution.js";
import { inspectCommand } from "./commands/inspect.js";
import { diffCommand } from "./commands/diff.js";
import { demoCommand } from "./commands/demo.js";
import { checkConfigCommand } from "./commands/check-config.js";
import { driftReportCommand } from "./commands/drift-report.js";
import { gatewayCommand } from "./commands/gateway.js";
import { migrateCommand } from "./commands/migrate.js";
import { approveCommand } from "./commands/approve.js";
import { bundleCreateCommand } from "./commands/bundle-create.js";
import { bundleVerifyCommand } from "./commands/bundle-verify.js";
import { generateCommand } from "./commands/generate.js";

const program = new Command();

program
  .name("sanna")
  .description("Trust infrastructure for AI agents")
  .version("0.1.0");

program.addCommand(initCommand);
program.addCommand(keygenCommand);
program.addCommand(signCommand);
program.addCommand(verifyCommand);
program.addCommand(verifyConstitutionCommand);
program.addCommand(inspectCommand);
program.addCommand(diffCommand);
program.addCommand(demoCommand);
program.addCommand(checkConfigCommand);
program.addCommand(driftReportCommand);
program.addCommand(gatewayCommand);
program.addCommand(migrateCommand);
program.addCommand(approveCommand);
program.addCommand(bundleCreateCommand);
program.addCommand(bundleVerifyCommand);
program.addCommand(generateCommand);

program.parse();
