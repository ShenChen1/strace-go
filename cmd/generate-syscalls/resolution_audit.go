package main

import (
	"fmt"
	"io"
	"sort"
)

const resolutionAuditHeader = "id\tname\tsource\targs\targ_types"

func writeResolutionAudit(stdout io.Writer, loader syscallMetadataResolutionLoader) error {
	if loader == nil {
		return fmt.Errorf("metadata resolution loader is unavailable")
	}
	resolutions, err := loader.LoadWithResolution()
	if err != nil {
		return fmt.Errorf("load metadata resolution: %w", err)
	}
	if _, err := fmt.Fprintln(stdout, resolutionAuditHeader); err != nil {
		return fmt.Errorf("write resolution audit header: %w", err)
	}
	ids := sortedResolutionIDs(resolutions)
	for _, id := range ids {
		if err := writeResolutionAuditRow(stdout, id, resolutions[id]); err != nil {
			return err
		}
	}
	return nil
}

func sortedResolutionIDs(resolutions map[int]syscallMetadataResolution) []int {
	ids := make([]int, 0, len(resolutions))
	for id := range resolutions {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func writeResolutionAuditRow(stdout io.Writer, id int, resolution syscallMetadataResolution) error {
	_, err := fmt.Fprintf(stdout, "%d\t%s\t%s\t%s\t%s\n",
		id,
		resolution.Meta.Name,
		resolution.Source,
		joinAuditValues(resolution.Meta.Args),
		joinAuditValues(resolution.Meta.ArgTypes),
	)
	if err != nil {
		return fmt.Errorf("write resolution audit row %d: %w", id, err)
	}
	return nil
}
