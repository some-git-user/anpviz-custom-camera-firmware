# camhost.tcl -- shared host resolution for the expect scripts.
#
#   source [file join [file dirname [info script]] camhost.tcl]
#   set host [cam_host $argv ?ymf46d]
#
# Resolution:
#   * an argument that already looks like an IPv4 literal is used as-is
#   * anything else is treated as a camera KEY (ym500l, ymf46d, default,
#     staging) and resolved via the ./cam helper, which reads the gitignored
#     tools/cameras.conf
#   * no argument at all -> the conf's `default`
#
# WHY: this repo used to hardcode our bench addresses (192.168.111.x) in every
# script. It is a public repo, so real addresses now live only in the
# gitignored tools/cameras.conf and are resolved through ./cam.
#
# Tcl has no access to the caller's cwd assumptions, so we locate ./cam relative
# to this file, which lives next to it in tools/.

proc cam_host {argv {fallback default}} {
    set here [file dirname [info script]]
    set cam  [file join $here cam]

    set want $fallback
    if {[llength $argv] >= 1 && [lindex $argv 0] ne ""} {
        set want [lindex $argv 0]
    }

    # Already an IPv4 literal? Use it directly, no lookup needed.
    if {[regexp {^[0-9]{1,3}(\.[0-9]{1,3}){3}$} $want]} {
        return $want
    }

    if {![file executable $cam]} {
        error "cannot resolve host '$want': $cam is missing or not executable"
    }

    if {[catch {exec $cam $want} ip]} {
        error "cannot resolve host '$want': $ip"
    }
    set ip [string trim $ip]
    if {$ip eq ""} {
        error "cannot resolve host '$want': empty answer from $cam"
    }
    return $ip
}
