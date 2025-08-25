/*
 * Copyright (c) 2016, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package server

import (
	"regexp"
	"strings"
	"testing"
)

func camelToSnake(s string) string {
	re := regexp.MustCompile("(.)([A-Z][a-z]+)")
	s = re.ReplaceAllString(s, "${1}_${2}")
	re = regexp.MustCompile("([a-z0-9])([A-Z])")
	s = re.ReplaceAllString(s, "${1}_${2}")

	return strings.ToLower(s)
}

func protoMapToLogFields(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for k, v := range m {
		if nestedMap, ok := v.(map[string]interface{}); ok {
			if len(nestedMap) == 0 {
				continue
			}

			for nestedKey, nestedValue := range nestedMap {
				// If the nested map is a metadata map, unnest it 1 additional level
				if strings.HasPrefix(nestedKey, "metadata") {
					if metadataObj, ok := nestedValue.(map[string]interface{}); ok {
						if len(metadataObj) == 0 {
							continue
						}

						for metaKey, metaValue := range metadataObj {
							result[camelToSnake(metaKey)] = metaValue
						}
					}
				} else {
					result[camelToSnake(nestedKey)] = nestedValue
				}
			}
		} else {
			result[camelToSnake(k)] = v
		}
	}

	return result
}

func TestPB_OSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
			doLogProtobuf:        true,
		})
}
