# F5 Log Visidata Plugin

This plugin supports the default log format for:
  - `/var/log/ltm*`
  - `/var/log/gtm*`
  - `/var/log/apm*`
  - `/var/log/audit*`

It extracts common log entries, particularly around monitoring, iRules and configuration change audits. It tries to extract data into common fields to assist rapid filtering.

## Requirements

[Visidata 2.x](https://www.visidata.org)

## Installation

Inside visidata, `<space>` to start a command, `open-plugins` to open the plugin sheet, scroll to `f5log` and press `a` to install the latest version.

## Configuration

`f5log_object_regex` provides a simple way to perform a regex on an object name extracted by a splitter and get extra columns out of it. This is very useful when objectnames have a structure. Simply use named groups in your regex to get named columns out.

Regex:
```(?:/Common/)(?P<site>[^-]+)-(?P<vstype>[^-]+)-(?P<application>[^-]+)```

```
/Common/newyork-www-banking1

... | site    | vstype | appliction | ...
... | newyork | www    | banking1   | ...
```
