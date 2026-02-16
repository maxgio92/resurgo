package resurgo

// Arch represents a CPU architecture.
type Arch string

// Supported architectures.
const (
	ArchAMD64 Arch = "amd64"
	ArchARM64 Arch = "arm64"
)

// PrologueType represents the type of function prologue.
type PrologueType string

// Recognized x86_64 function prologue patterns.
const (
	PrologueClassic        PrologueType = "classic"
	PrologueNoFramePointer PrologueType = "no-frame-pointer"
	ProloguePushOnly       PrologueType = "push-only"
	PrologueLEABased       PrologueType = "lea-based"
)

// Recognized ARM64 function prologue patterns.
const (
	PrologueSTPFramePair PrologueType = "stp-frame-pair"
	PrologueSTRLRPreIndex PrologueType = "str-lr-preindex"
	PrologueSubSP        PrologueType = "sub-sp"
	PrologueSTPOnly      PrologueType = "stp-only"
)

// Prologue represents a detected function prologue.
type Prologue struct {
	Address      uint64       `json:"address"`
	Type         PrologueType `json:"type"`
	Instructions string       `json:"instructions"`
}
