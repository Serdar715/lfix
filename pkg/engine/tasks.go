package engine

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Serdar715/lfix/pkg/mutations"
)

// GenerateTasks creates and sends tasks to the tasks channel based on the target, payloads, and options.
func GenerateTasks(target string, payloads []string, postData string, method string, targetHeader string, staticHeaders map[string]string, useMutation bool, tasks chan<- Task) {
	target = strings.ReplaceAll(target, "\\", "")

	hasFuzz := strings.Contains(target, "FUZZ") ||
		strings.Contains(postData, "FUZZ") ||
		strings.Contains(targetHeader, "FUZZ")

	for _, rawPayload := range payloads {
		payloadMutations := []string{rawPayload}
		if useMutation {
			payloadMutations = mutations.GetMutations(rawPayload, "")
		}

		for _, payload := range payloadMutations {
			if hasFuzz {
				finalURL := strings.ReplaceAll(target, "FUZZ", payload)
				finalPost := strings.ReplaceAll(postData, "FUZZ", payload)

				headers := copyMap(staticHeaders)
				if targetHeader != "" {
					parts := strings.SplitN(targetHeader, ":", 2)
					if len(parts) == 2 {
						k := strings.TrimSpace(parts[0])
						v := strings.TrimSpace(parts[1])
						headers[k] = strings.ReplaceAll(v, "FUZZ", payload)
					}
				}

				tasks <- Task{
					URL:            finalURL,
					OriginalURL:    target,
					Method:         method,
					PostData:       finalPost,
					Headers:        headers,
					Payload:        rawPayload,
					InjectionPoint: "CUSTOM_FUZZ",
				}
				continue
			}

			u, err := url.Parse(target)
			if err != nil {
				continue
			}

			// URL Query Params
			queryParams := u.Query()
			for attackParam := range queryParams {
				var queryStringParts []string
				for key, values := range queryParams {
					if key == attackParam {
						queryStringParts = append(queryStringParts, fmt.Sprintf("%s=%s", key, payload))
					} else {
						for _, val := range values {
							queryStringParts = append(queryStringParts, fmt.Sprintf("%s=%s", key, url.QueryEscape(val)))
						}
					}
				}
				uClone := *u
				uClone.RawQuery = strings.Join(queryStringParts, "&")
				tasks <- Task{
					URL:            uClone.String(),
					OriginalURL:    target,
					Method:         method,
					PostData:       postData,
					Headers:        staticHeaders,
					Payload:        rawPayload,
					InjectionPoint: "URL_" + attackParam,
				}
			}

			// POST Params
			if method == "POST" && postData != "" {
				postParams, err := url.ParseQuery(postData)
				if err == nil {
					for attackParam := range postParams {
						var postBodyParts []string
						for key, values := range postParams {
							if key == attackParam {
								// URL encode the payload for POST body
								postBodyParts = append(postBodyParts, fmt.Sprintf("%s=%s", key, url.QueryEscape(payload)))
							} else {
								for _, val := range values {
									postBodyParts = append(postBodyParts, fmt.Sprintf("%s=%s", key, url.QueryEscape(val)))
								}
							}
						}
						newPostData := strings.Join(postBodyParts, "&")
						tasks <- Task{
							URL:            target,
							OriginalURL:    target,
							Method:         "POST",
							PostData:       newPostData,
							Headers:        staticHeaders,
							Payload:        rawPayload,
							InjectionPoint: "POST_" + attackParam,
						}
					}
				}
			}

			// Header Injection
			if targetHeader != "" {
				cleanKey := strings.TrimSpace(strings.SplitN(targetHeader, ":", 2)[0])
				if cleanKey != "" {
					h := copyMap(staticHeaders)
					h[cleanKey] = payload
					tasks <- Task{
						URL:            target,
						OriginalURL:    target,
						Method:         method,
						PostData:       postData,
						Headers:        h,
						Payload:        rawPayload,
						InjectionPoint: "HEADER_" + cleanKey,
					}
				}
			}
		}
	}
}

// copyMap creates a shallow copy of a map.
func copyMap(original map[string]string) map[string]string {
	if original == nil {
		return make(map[string]string)
	}
	c := make(map[string]string)
	for k, v := range original {
		c[k] = v
	}
	return c
}
