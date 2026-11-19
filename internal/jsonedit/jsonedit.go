// Package jsonedit parses and re-serialises JSON while preserving object key
// order and number literals, so installers can edit user settings files
// without reshuffling them.
package jsonedit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Object is an ordered JSON object. Values are *Object, []any, string,
// json.Number, bool or nil.
type Object struct {
	keys []string
	vals map[string]any
}

// NewObject returns an empty object.
func NewObject() *Object { return &Object{vals: map[string]any{}} }

// Get returns the value for key.
func (o *Object) Get(key string) (any, bool) { v, ok := o.vals[key]; return v, ok }

// Set adds or replaces key, keeping the original position of existing keys.
func (o *Object) Set(key string, v any) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
}

// Delete removes key.
func (o *Object) Delete(key string) {
	if _, ok := o.vals[key]; !ok {
		return
	}
	delete(o.vals, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

// Len is the number of keys.
func (o *Object) Len() int { return len(o.keys) }

// Parse decodes a single JSON value.
func Parse(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := NewObject()
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errors.New("invalid object key")
				}
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj.Set(key, v)
			}
			_, err := dec.Token()
			return obj, err
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			_, err := dec.Token()
			return arr, err
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		return t, nil
	}
}

// Marshal renders v with two-space indentation and a trailing newline, like jq.
func Marshal(v any) ([]byte, error) {
	var b strings.Builder
	if err := write(&b, v, ""); err != nil {
		return nil, err
	}
	b.WriteString("\n")
	return []byte(b.String()), nil
}

func writeString(b *strings.Builder, s string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	b.Write(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return nil
}

func write(b *strings.Builder, v any, indent string) error {
	inner := indent + "  "
	switch t := v.(type) {
	case *Object:
		if t.Len() == 0 {
			b.WriteString("{}")
			return nil
		}
		b.WriteString("{\n")
		for i, k := range t.keys {
			b.WriteString(inner)
			if err := writeString(b, k); err != nil {
				return err
			}
			b.WriteString(": ")
			if err := write(b, t.vals[k], inner); err != nil {
				return err
			}
			if i < len(t.keys)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + "}")
	case []any:
		if len(t) == 0 {
			b.WriteString("[]")
			return nil
		}
		b.WriteString("[\n")
		for i, e := range t {
			b.WriteString(inner)
			if err := write(b, e, inner); err != nil {
				return err
			}
			if i < len(t)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + "]")
	case string:
		return writeString(b, t)
	case json.Number:
		b.WriteString(t.String())
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case nil:
		b.WriteString("null")
	case int:
		fmt.Fprintf(b, "%d", t)
	default:
		return fmt.Errorf("unsupported JSON value %T", v)
	}
	return nil
}
