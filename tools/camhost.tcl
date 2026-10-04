# camhost.tcl -- get a camera address for the expect scripts, asking if needed.
#
#   source [file join [file dirname [info script]] camhost.tcl]
#   set host [cam_host $argv]
#
# The address comes from, in order:
#   1. the argument (an IPv4 address or hostname)
#   2. the CAM_IP environment variable
#   3. a prompt on the terminal
#
# Tcl cannot read from stdin reliably inside expect's spawn flow, so this must be
# called BEFORE spawning telnet. All the expect scripts do that.

proc cam_host_is_valid {host} {
    # IPv4 dotted quad, or a plain hostname.
    if {[regexp {^[0-9]{1,3}(\.[0-9]{1,3}){3}$} $host]} { return 1 }
    if {[regexp {^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$} $host]} { return 1 }
    return 0
}

# cam_host argv ?prompt?
# Takes the argv list, returns a host string. Prompts if nothing was supplied.
proc cam_host {argv {prompt "camera IP"}} {
    global env
    set host ""
    if {[llength $argv] >= 1} { set host [string trim [lindex $argv 0]] }
    if {$host eq "" && [info exists env(CAM_IP)]} { set host [string trim $env(CAM_IP)] }

    if {$host eq ""} {
        if {![interactive]} {
            puts stderr "cam: no camera address given."
            puts stderr "     pass it as an argument, or set CAM_IP=1.2.3.4"
            exit 1
        }
        puts -nonewline stderr "$prompt: "
        flush stderr
        gets stdin host
        set host [string trim $host]
    }

    if {$host eq ""} {
        puts stderr "cam: no camera address given."
        exit 1
    }
    if {![cam_host_is_valid $host]} {
        puts stderr "cam: '$host' is not an IPv4 address or hostname."
        exit 1
    }
    return $host
}

# Is stdin a terminal we can prompt on?
# Tcl has no file isatty; the `tty` command prints /dev/tty when stdin is a
# terminal and says "not a tty" otherwise.
proc interactive {} {
    if {[catch {exec tty} out]} { return 0 }
    return [expr {[string first "not a tty" $out] == -1}]
}
