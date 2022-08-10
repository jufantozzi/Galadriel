package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRunCommand(t *testing.T) {
	called := false

	runServerFn = func() {
		called = true
	}

	cmd := NewRunCmd()
	cmd.Execute()

	assert.Equal(t, called, true)
}
