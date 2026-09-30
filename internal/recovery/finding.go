package recovery

// FindingCategory groups findings by the verification stage that produced
// them so the recovery report can separate format, reference, idempotency
// index and summary problems.
type FindingCategory string

const (
	CategoryFormat    FindingCategory = "format"
	CategoryReference FindingCategory = "reference"
	CategoryIndex     FindingCategory = "index"
	CategorySummary   FindingCategory = "summary"
)

// Finding is a single deterministic validation problem located in the
// candidate snapshot. Ref is the offending entity id or index key when one
// can be identified.
type Finding struct {
	Category FindingCategory `json:"category"`
	Code     string          `json:"code"`
	Message  string          `json:"message"`
	Ref      string          `json:"ref,omitempty"`
}

func (f Finding) String() string {
	if f.Ref == "" {
		return string(f.Category) + "/" + f.Code + ": " + f.Message
	}
	return string(f.Category) + "/" + f.Code + " [" + f.Ref + "]: " + f.Message
}

type findingCollector struct {
	items []Finding
}

func (c *findingCollector) add(category FindingCategory, code, message, ref string) {
	c.items = append(c.items, Finding{
		Category: category,
		Code:     code,
		Message:  message,
		Ref:      ref,
	})
}

func (c *findingCollector) format(code, message, ref string) {
	c.add(CategoryFormat, code, message, ref)
}

func (c *findingCollector) reference(code, message, ref string) {
	c.add(CategoryReference, code, message, ref)
}

func (c *findingCollector) index(code, message, ref string) {
	c.add(CategoryIndex, code, message, ref)
}

func (c *findingCollector) summary(code, message, ref string) {
	c.add(CategorySummary, code, message, ref)
}
