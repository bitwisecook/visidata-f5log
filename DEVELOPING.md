# Developing

## Structure

The core of the plugin is the `F5LogSheet` class, which just implements `iterload`.

On each line of input the regex `re_f5log` is run against it to extract the basic information including:
  - `date_time`
  - `host`
  - `level`
  - `process`,`proc_pid`
  - `logid1`
  - `logid2`
  - `message`

Then `logid1` is looked up in dictionary `F5LogSheet.splitters`. If found and the log text is not one of the `F5LogSheet.no_split_logs` then we call the appropriate splitter function.

A splitter function is a generator that will yield a series of dictionaries that will get summed into the `kv` of the `F5LogRow`.

This dictionary will be unpacked into columns, so we hold a list of `extra_cols` and will call the `F5LogSheet.addColumn` if a column isn't present.

This row is then yielded from `iterload`.

A couple of fancy types are present to assist the log display, `ip_address`, `hexint` and `delta_t`.

For debugging purposes it can be useful to uncomment the `rawmsg` to have the entire line present in the UI.

## Naming new columns

Use `object` for the main object being referred to in a log, for example the `pool` in a monitor log, or the `irule` in a TCL error log.

Any time duration should be in seconds as `duration_s`.

Any monitor should use `new_status` and `prev_status` as appropriate.

Any mention of an IP should attempt to use `src_ip` / `dst_ip` (and/or `*_port`) as appropriate. For instance in a monitor use `dst_ip`.