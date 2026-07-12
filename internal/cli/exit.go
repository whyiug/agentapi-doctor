package cli

const (
	ExitSuccess            = 0
	ExitTargetFailure      = 1
	ExitInput              = 2
	ExitInfrastructure     = 3
	ExitIncomplete         = 4
	ExitPermission         = 5
	ExitBaselineRegression = 6
	ExitInterrupted        = 130
)

var exitPriority = map[int]int{
	ExitSuccess:            0,
	ExitTargetFailure:      1,
	ExitBaselineRegression: 2,
	ExitIncomplete:         3,
	ExitInfrastructure:     4,
	ExitPermission:         5,
	ExitInput:              6,
	ExitInterrupted:        7,
}

func PrimaryExitCode(conditions []int) int {
	primary := ExitSuccess
	for _, condition := range conditions {
		if exitPriority[condition] > exitPriority[primary] {
			primary = condition
		}
	}
	return primary
}
