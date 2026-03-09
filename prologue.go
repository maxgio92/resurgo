package resurgo

const (
	// Supported architectures.
	ArchAMD64 Arch = "amd64"
	ArchARM64 Arch = "arm64"

	// DetectionPrologueOnly indicates the candidate was found by prologue
	// pattern matching only.
	DetectionPrologueOnly DetectionType = "prologue-only"

	// Recognized x86_64 function prologue patterns.
	PrologueClassic        PrologueType = "classic"
	PrologueNoFramePointer PrologueType = "no-frame-pointer"
	ProloguePushOnly       PrologueType = "push-only"
	PrologueLEABased       PrologueType = "lea-based"

	// Recognized ARM64 function prologue patterns.
	PrologueSTPFramePair  PrologueType = "stp-frame-pair"
	PrologueSTRLRPreIndex PrologueType = "str-lr-preindex"
	PrologueSubSP         PrologueType = "sub-sp"
	PrologueSTPOnly       PrologueType = "stp-only"
)

// Arch represents a CPU architecture.
type Arch string

// PrologueType represents the type of function prologue.
type PrologueType string

// Prologue represents a detected function prologue.
type Prologue struct {
	// Address is the virtual address of the detected prologue.
	Address uint64 `json:"address"`
	// Type is the matched prologue pattern.
	Type PrologueType `json:"type"`
	// Instructions is a human-readable representation of the matched
	// prologue instructions.
	Instructions string `json:"instructions"`
}
