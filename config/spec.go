package config

import (
	"encoding/json"
	"fmt"
	"os"
)

func LoadSpec(cPath string) (spec *Spec, err error) {
	cf, err := os.Open(cPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("JSON specification file %s not found", cPath)
		}
		return nil, err
	}
	defer cf.Close()
	if err = json.NewDecoder(cf).Decode(&spec); err != nil {
		return nil, err
	}
	return spec, validateProcessSpec(spec.Process)
}
