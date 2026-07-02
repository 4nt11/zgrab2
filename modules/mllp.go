package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/mllp"
)

func init() {
	zgrab2.RegisterModule(mllp.NewModule())
}
