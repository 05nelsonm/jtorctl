// Copyright 2005 Nick Mathewson, Roger Dingledine
// See LICENSE file for copying information
package net.freehaven.tor.control;

import org.jetbrains.annotations.NotNull;

/** A single key-value pair from Tor's configuration. */
public class ConfigEntry {
    @NotNull public final String key;
    @NotNull public final String value;
    public final boolean is_default;

    public ConfigEntry(@NotNull String k, @NotNull String v) {
        key = k;
        value = v;
        is_default = false;
    }
    public ConfigEntry(@NotNull String k) {
        key = k;
        value = "";
        is_default = true;
    }
}
