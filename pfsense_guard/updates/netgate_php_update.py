"""Netgate-published command sets for the October 2026 PHP security updates.

These are displayed for administrator review only. They are not run automatically.
"""

METHOD_REBOOT = [
    "pfSense-upgrade -c",
    "pkg upgrade -y",
    "pkg upgrade -fy pfSense-pkg-WireGuard",
    "/etc/rc.reboot",
]

METHOD_RESTART_WEB_SERVICES = [
    "pfSense-upgrade -c",
    "pkg upgrade -y",
    "pkg upgrade -fy pfSense-pkg-WireGuard",
    "/etc/rc.php-fpm_restart",
    "/etc/rc.restart_webgui",
    "/etc/rc.captiveportal_configure",
]

METHOD_RESTART_GUI_ONLY = [
    "pfSense-upgrade -c",
    "pkg upgrade -y",
    "pkg upgrade -fy pfSense-pkg-WireGuard",
    "/etc/rc.php-fpm_restart",
    "/etc/rc.restart_webgui",
]


def command_plan(method: str) -> list[str]:
    if method == "reboot":
        return list(METHOD_REBOOT)
    if method == "restart":
        return list(METHOD_RESTART_WEB_SERVICES)
    if method == "restart-gui-only":
        return list(METHOD_RESTART_GUI_ONLY)
    raise ValueError("method must be 'reboot', 'restart', or 'restart-gui-only'")
