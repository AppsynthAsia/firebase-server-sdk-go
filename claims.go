package firebase

// Claims to be stored in a custom token (and made available to security rules
// in Database, Storage, etc.).  These must be serializable to JSON
// (e.g. contains only Maps, Arrays, Strings, Booleans, Numbers, etc.).
type Claims map[string]interface{}

// Get retrieves the value corresponding with key from the Claims.
func (c Claims) Get(key string) interface{} {
	if c == nil {
		return nil
	}
	return c[key]
}

// Set sets Claims[key] = val. It'll overwrite without warning.
func (c Claims) Set(key string, val interface{}) {
	c[key] = val
}

// Del removes the value that corresponds with key from the Claims.
func (c Claims) Del(key string) {
	delete(c, key)
}

// Has returns true if a value for the given key exists inside the Claims.
func (c Claims) Has(key string) bool {
	_, ok := c[key]
	return ok
}