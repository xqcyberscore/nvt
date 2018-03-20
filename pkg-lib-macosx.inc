###################################################################
# OpenVAS Vulnerability Test
#
# Mac OS X LSC helper library
#
# LSS-NVT-2010-011
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

# Mac OS X update pkg name consists of two parts:
# the fixed part and the diff part
# This function looks up all the pkgs in the list
# that match the fixed part, and checks if the diff part
# in the list is greater that the given one.
#

include("version_func.inc");

function isosxpkgvuln(fixed, diff) {
    list=get_kb_item("ssh/login/osx_pkgs");
    if (!list) exit (0);
    max_diff=0;
    list=split(list);
    foreach i (keys(list)) if (fixed >< chomp(list[i])) {
        s=(substr(chomp(list[i]), strlen(fixed), strlen(fixed)+strlen(diff)-1));
        if (s>max_diff) {max_diff = s;}
    }
    if (diff>max_diff) return 1; else return 0;
}

# Checks if pkg name exists in pkg list #
function pkg_in_list(name, version) {
    list=get_kb_item("ssh/login/osx_pkgs");
    if (!list) exit (0);
    list=split(list);
    foreach i (keys(list)) if (name == chomp(list[i])) {
        if (version == 0 || version == chomp(list[i+1])) return 1;
    }
    return 0;
}

# Returns the release (major) version of Mac OS X #
function osx_rls_name(rls) {
    r=eregmatch(pattern:"[a-z A-Z]+[0-9]+\.[0-9]+", string:rls);
    return r[0];
}

# Returns the full (minor) version of Mac OS X #
function osx_ver(ver) {
    v=eregmatch(pattern:"[0-9.]+", string:ver);
    return v[0];
}

# Checks if the release is less than the ones in the list #
function rlsnotsupported(rls, list) {
    # find the minimum version in the list
    min = list[0];
    foreach ver (list) {
        if (version_is_less(ver, min)) { min=ver;}
    }

    # compare the release version against the
    # minimum version from the version list
    if (version_is_less_equal(rls, min, false, false)) return 1; else return 0;

    # according to linked CVEs the versions commonly supplied in list
    # INCLUDE the last vulnerable release so the above condition
    # should be less than or equal to
}
