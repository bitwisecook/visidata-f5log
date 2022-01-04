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

### Using the built-in plugin manager

Inside visidata, `<space>` to start a command, `open-plugins` to open the plugin sheet, scroll to `f5log` and press `a` to install the latest version.

### Manual Installation on MacOS / Linux / *BSD

```sh
pip3 install pytz
mkdir -p .visidata/plugins
curl -o ~/.visidata/plugins/f5log.py https://raw.githubusercontent.com/bitwisecook/visidata-f5log/0.3.1/f5log.py
echo 'import plugins.f5log' >> ~/.visidata/plugins/init.py
```

## Configuration

`f5log_object_regex` provides a simple way to perform a regex on an object name extracted by a splitter and get extra columns out of it. This is very useful when objectnames have a structure. Simply use [named groups](https://docs.python.org/3/howto/regex.html#non-capturing-and-named-groups) in your regex to get named columns out.

Regex:
```(?:/Common/)(?P<site>[^-]+)-(?P<vstype>[^-]+)-(?P<application>[^-]+)```

```
/Common/newyork-www-banking1

... | site    | vstype | appliction | ...
... | newyork | www    | banking1   | ...
```

### Adding to `.visidatarc`

```sh
echo 'visidata.vd.options.set("f5log_object_regex", r"(?:/Common/)(?P<site>[^-]+)-(?P<vstype>[^-]+)-(?P<application>[^-]+)", obj="global")' > ~/.visidatarc
```