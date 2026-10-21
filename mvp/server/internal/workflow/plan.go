package workflow

import (
	"encoding/json"
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// StagePlan is one approval stage of a resolved path.
type StagePlan struct {
	Step               string  `json:"step"`
	Label              string  `json:"label"`
	Approver           string  `json:"approver"`
	GroupID            string  `json:"group_id,omitempty"`
	HoldHours          float64 `json:"hold_hours,omitempty"` // the stage opens this long after the one before it was approved
	EscalateAfterHours float64 `json:"escalate_after_hours"`
}

// Kind is the approval stage kind (internal/store) the engine stores for this stage. A group
// or an explicit owner is a stage of kind owner: the assignee, or the group, says who.
func (s StagePlan) Kind() string {
	switch s.Approver {
	case ApproverManager:
		return store.StageManager
	case ApproverDecider:
		return store.StageDecider
	}
	return store.StageOwner
}

// Action is a notice a path sends. After is the index of the approval stage whose approval
// triggers it (-1: when the request is filed).
type Action struct {
	Step    string `json:"step"`
	After   int    `json:"after"`
	Notify  string `json:"notify"`
	GroupID string `json:"group_id,omitempty"`
	Message string `json:"message,omitempty"`
}

// Plan is the path of a definition selected by a request's attributes. The run keeps it as
// JSON, so the request follows it whatever is edited later.
type Plan struct {
	Workflow       string      `json:"workflow"`
	Version        int         `json:"version"`
	Path           []string    `json:"path"`
	Stages         []StagePlan `json:"stages"`
	Actions        []Action    `json:"actions"`
	Questionnaires []string    `json:"questionnaires"`
	Provision      bool        `json:"provision"`
}

// StageAt returns the plan of stage idx, or nil.
func (p *Plan) StageAt(idx int) *StagePlan {
	if p == nil || idx < 0 || idx >= len(p.Stages) {
		return nil
	}
	return &p.Stages[idx]
}

// Parse reads a stored plan.
func Parse(raw string) (*Plan, error) {
	var p Plan
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

var approverLabels = map[string]string{ApproverManager: "Manager approval", ApproverOwner: "Owner approval",
	ApproverGroup: "Group approval", ApproverDecider: "Decider approval", ApproverOldOwner: "Current owner approval",
	ApproverNewOwner: "New owner approval"}

// Compile follows a valid definition from its first step, taking each condition's branch by
// the attributes, and returns the resolved path.
func (d Definition) Compile(workflowID string, version int, attrs map[string]string) (*Plan, error) {
	p := &Plan{Workflow: workflowID, Version: version, Path: []string{}, Stages: []StagePlan{}, Actions: []Action{},
		Questionnaires: []string{}}
	idx := map[string]int{}
	for i, s := range d.Steps {
		idx[s.ID] = i
	}
	hold := 0.0
	cur := 0
	for n := 0; cur < len(d.Steps); n++ {
		if n > len(d.Steps) {
			return nil, errors.New("workflow: the definition loops")
		}
		s := d.Steps[cur]
		p.Path = append(p.Path, s.ID)
		next := cur + 1
		if s.Next != "" {
			next = len(d.Steps)
			if s.Next != End {
				next = idx[s.Next]
			}
		}
		switch s.Type {
		case TypeApproval:
			label := s.Name
			if label == "" {
				label = approverLabels[s.Approver]
			}
			esc := s.EscalateAfterHours
			if esc == 0 {
				esc = DefaultEscalateHours
			}
			p.Stages = append(p.Stages, StagePlan{Step: s.ID, Label: label, Approver: s.Approver, GroupID: s.GroupID,
				HoldHours: hold, EscalateAfterHours: esc})
			hold = 0
		case TypeWait:
			hold += s.Hours
		case TypeQuestionnaire:
			p.Questionnaires = append(p.Questionnaires, s.QuestionnaireID)
		case TypeNotify:
			p.Actions = append(p.Actions, Action{Step: s.ID, After: len(p.Stages) - 1, Notify: s.Notify, GroupID: s.GroupID,
				Message: s.Message})
		case TypeProvisioning:
			p.Provision = true
		case TypeCondition:
			take := s.Else
			if s.When != nil && s.When.Eval(attrs) {
				take = s.Then
			}
			next = len(d.Steps)
			if take != End {
				next = idx[take]
			}
		}
		cur = next
	}
	if len(p.Stages) == 0 {
		return nil, errors.New("workflow: the path has no approval")
	}
	return p, nil
}
