package cli

import (
	"fmt"

	"github.com/HewlettPackard/galadriel/cmd/server/util"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list <members | relationships>",
	Short: "Lists members and relationships",
}

var listMembersCmd = &cobra.Command{
	Use:   "members",
	Args:  cobra.ExactArgs(0),
	Short: "Lists all the members.",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := util.NewServerClient(defaultSocketPath)
		members, err := c.ListMembers()
		if err != nil {
			return err
		}

		if len(members) == 0 {
			fmt.Println("No members found")
			return nil
		}

		for _, m := range members {
			fmt.Printf("ID: %s\n", m.ID)
			fmt.Printf("Trust Domain: %s\n", m.TrustDomain)
			fmt.Println()
		}

		return nil
	},
}

var listRelationshipsCmd = &cobra.Command{
	Use:   "relationships",
	Args:  cobra.ExactArgs(0),
	Short: "Lists all the relationships.",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := util.NewServerClient(defaultSocketPath)
		rels, err := c.ListRelationships()
		if err != nil {
			return err
		}

		if len(rels) == 0 {
			fmt.Println("No relationships found")
			return nil
		}

		for _, r := range rels {
			fmt.Printf("ID: %s\n", r.ID)
			fmt.Printf("Trust Domain A: %s\n", r.MemberA.TrustDomain.String())
			fmt.Printf("Trust Domain B: %s\n", r.MemberB.TrustDomain.String())
			fmt.Println()
		}

		return nil
	},
}

func init() {
	listCmd.AddCommand(listMembersCmd)
	listCmd.AddCommand(listRelationshipsCmd)

	RootCmd.AddCommand(listCmd)
}
