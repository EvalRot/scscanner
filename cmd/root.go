package cmd

var rootCmd = &cobra.Command{
	Use:   "hugo",
	Short: "Hugo is a very fast static site generator",
	Long: `A Fast and Flexible Static Site Generator built with
				  love by spf13 and friends in Go.
				  Complete documentation is available at https://gohugo.io/documentation/`,
	Run: func(cmd *cobra.Command, args []string) {
	  // Do Stuff Here
	},
  }

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// parse target as global flag
	RootCmd.PersistentFlags().StringSliceVarP(&options.Scan.Inputs, "target", "t", []string{}, "The target you want to run/execute")
	RootCmd.PersistentFlags().StringVarP(&options.Scan.InputList, "targets", "T", "", "List of target as a file")

	// recon command
	RootCmd.PersistentFlags().IntVarP(&options.Concurrency, "concurrency", "c", 1, "Concurrency level (recommend to keep it as 1 on machine has RAM smaller than 2GB)")
	RootCmd.PersistentFlags().StringSliceVarP(&options.Scan.Modules, "modules", "m", []string{}, "Recon modules to run")
	RootCmd.PersistentFlags().StringVarP(&options.Scan.Flow, "flow", "f", "general", "Flow name for running (default: general)")
	RootCmd.PersistentFlags().StringVarP(&options.Scan.CustomWorkspace, "workspace", "w", "", "Name of workspace (default is same as target)")
	RootCmd.PersistentFlags().StringSliceVarP(&options.Scan.Params, "params", "p", []string{}, "Custom params -p='foo=bar' (Multiple -p flags are accepted)")
	RootCmd.PersistentFlags().StringVar(&options.Scan.SuffixName, "suffix", "", "Suffix string for file converted (default: randomly)")
	RootCmd.PersistentFlags().IntVarP(&options.Threads, "threads-hold", "B", 0, "Threads hold for each module (default: number of CPUs)")
	RootCmd.PersistentFlags().StringVar(&options.Tactics, "tactic", "default", "Choosing the tactic for running workflow from [default aggressive gently]")

	RootCmd.SetHelpFunc(RootHelp)
	cobra.OnInitialize(initConfig)
}