package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/linkedca"

	"github.com/smallstep/certificates/authority/admin"
	adminDBNosql "github.com/smallstep/certificates/authority/admin/db/nosql"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/db"
)

func init() {
	command.Register(cli.Command{
		Name:      "import",
		Usage:     "import provisioners and admins from an export file",
		UsageText: "**step-ca import** <config> <export-file> [**--dry-run**]",
		Action:    importAction,
		Description: `**step-ca import** imports provisioners and admins from an export file
into the CA's admin database.

This command is used to migrate from a Linked CA to a standalone CA, or to
migrate provisioners and admins between standalone CAs.

The CA must be stopped before running this command.

## POSITIONAL ARGUMENTS

<config>
:  The ca.json configuration file. Must have 'authority.enableAdmin: true'
   and a database configured.

<export-file>
:  The export file created by 'step-ca export'.

## EXAMPLES

Import provisioners and admins from an export file:
'''
$ step-ca import $(step path)/config/ca.json export.json
'''

Preview the import without making changes:
'''
$ step-ca import $(step path)/config/ca.json export.json --dry-run
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "dry-run",
				Usage: "preview the import without making changes",
			},
		},
	})
}

func importAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	configFile := ctx.Args().Get(0)
	exportFile := ctx.Args().Get(1)
	dryRun := ctx.Bool("dry-run")

	// Load and validate configuration
	cfg, err := config.LoadConfiguration(configFile)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Check that enableAdmin is true
	if cfg.AuthorityConfig == nil || !cfg.AuthorityConfig.EnableAdmin {
		return errors.New("authority.enableAdmin must be true to use the import command")
	}

	// Check that a database is configured
	if cfg.DB == nil {
		return errors.New("a database must be configured to use the import command")
	}

	// Read and parse export file
	exportData, err := os.ReadFile(exportFile)
	if err != nil {
		return errors.Wrapf(err, "error reading export file %s", exportFile)
	}

	var export linkedca.ConfigurationResponse
	if err := protojson.Unmarshal(exportData, &export); err != nil {
		return errors.Wrap(err, "error parsing export file")
	}

	if dryRun {
		fmt.Println("=== DRY RUN - No changes will be made ===")
		fmt.Println()
	}

	// Open database
	authDB, err := db.New(cfg.DB)
	if err != nil {
		return errors.Wrap(err, "error opening database")
	}
	defer func() {
		if dbShutdown, ok := authDB.(interface{ Shutdown() error }); ok {
			dbShutdown.Shutdown()
		}
	}()

	// Get the nosql.DB interface from the wrapped DB
	nosqlDB, ok := authDB.(*db.DB)
	if !ok {
		return errors.New("database does not support admin operations")
	}

	// Initialize admin DB
	adminDB, err := adminDBNosql.New(nosqlDB.DB, admin.DefaultAuthorityID)
	if err != nil {
		return errors.Wrap(err, "error initializing admin database")
	}

	// Get existing provisioners for duplicate detection
	existingProvs, err := adminDB.GetProvisioners(context.Background())
	if err != nil {
		return errors.Wrap(err, "error getting existing provisioners")
	}

	// Build map of existing provisioner names to IDs
	existingProvsByName := make(map[string]string)
	for _, p := range existingProvs {
		existingProvsByName[p.Name] = p.Id
	}

	// Get existing admins for duplicate detection
	existingAdmins, err := adminDB.GetAdmins(context.Background())
	if err != nil {
		return errors.Wrap(err, "error getting existing admins")
	}

	// Build set of existing admin subject+provisioner combos
	existingAdminKeys := make(map[string]bool)
	for _, a := range existingAdmins {
		key := a.Subject + ":" + a.ProvisionerId
		existingAdminKeys[key] = true
	}

	// Track old ID to new ID mappings for provisioners
	provIDMap := make(map[string]string)

	// Import provisioners first (admins reference them)
	fmt.Printf("Importing %d provisioner(s)...\n", len(export.Provisioners))
	var provsCreated, provsSkipped int
	for _, prov := range export.Provisioners {
		oldID := prov.Id

		// Check for duplicate by name
		if existingID, exists := existingProvsByName[prov.Name]; exists {
			fmt.Printf("  Skipping provisioner %q: already exists\n", prov.Name)
			provIDMap[oldID] = existingID
			provsSkipped++
			continue
		}

		if dryRun {
			fmt.Printf("  Would create provisioner %q (type: %s)\n", prov.Name, prov.Type.String())
			// For dry run, map old ID to itself since we won't create new ones
			provIDMap[oldID] = oldID
			provsCreated++
			continue
		}

		// Clear ID so the database generates a new one
		prov.Id = ""

		if err := adminDB.CreateProvisioner(context.Background(), prov); err != nil {
			return errors.Wrapf(err, "error creating provisioner %q", prov.Name)
		}

		fmt.Printf("  Created provisioner %q (type: %s)\n", prov.Name, prov.Type.String())
		provIDMap[oldID] = prov.Id
		provsCreated++
	}

	// Import admins with remapped provisioner IDs
	fmt.Printf("Importing %d admin(s)...\n", len(export.Admins))
	var adminsCreated, adminsSkipped int
	for _, adm := range export.Admins {
		// Remap provisioner ID
		newProvID, ok := provIDMap[adm.ProvisionerId]
		if !ok {
			fmt.Printf("  Skipping admin %q: provisioner ID %s not found in export\n", adm.Subject, adm.ProvisionerId)
			adminsSkipped++
			continue
		}

		// Check for duplicate by subject+provisioner combo
		key := adm.Subject + ":" + newProvID
		if existingAdminKeys[key] {
			fmt.Printf("  Skipping admin %q: already exists for this provisioner\n", adm.Subject)
			adminsSkipped++
			continue
		}

		if dryRun {
			fmt.Printf("  Would create admin %q (type: %s)\n", adm.Subject, adm.Type.String())
			adminsCreated++
			continue
		}

		// Clear ID and update provisioner ID
		adm.Id = ""
		adm.ProvisionerId = newProvID

		if err := adminDB.CreateAdmin(context.Background(), adm); err != nil {
			return errors.Wrapf(err, "error creating admin %q", adm.Subject)
		}

		fmt.Printf("  Created admin %q (type: %s)\n", adm.Subject, adm.Type.String())
		adminsCreated++
	}

	fmt.Println()
	fmt.Printf("Import complete: %d provisioner(s) created, %d skipped; %d admin(s) created, %d skipped\n",
		provsCreated, provsSkipped, adminsCreated, adminsSkipped)

	if dryRun {
		fmt.Println()
		fmt.Println("=== DRY RUN - No changes were made ===")
		fmt.Println("Run without --dry-run to perform the import.")
	}

	return nil
}
