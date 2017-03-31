# OpenVAS Vulnerability Test include file
# $Id$
# Description: Check if debian package is up to date
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
# isdpkgvuln is intended to provide a quick way to verify that
# a given rpm, if it is installed, is vulnerable or not. The function
# isdpkgvuln returns 0 if it is not installed or is installed
# but up to date, and returns 1 if it is installed and vulnerable
#
# dpkgnorm is used for string normalization that helps us with cases
# were even revcomp can't handle things the way we would expect.
# For example, consider two subsequent releases of cups:
#     1.3.8-1lenny5
#     1.3.8-1+lenny6  (yes, this really happened, but makes the results
#                      of revcomp incorrectly determine which rev is later)
#     1.3.8-1.lenny7  (ok, this didn't for this example, but did in others)
# Normalization allows us to do things like change all instances to look like
#     1.3.8-1lennyX
# so that we can revcomp accurately determines which revision is the latest
# We're passing in rls so that we can use it if we need to - but for now,
# the only instances causing us problems are debian lenny



# This variable is defined at inclusion time. It's declared global and is set
# to True if isdpkgvuln() is called for an OS version and a package name that
# match the target's configuration. It allows the callers to distinguish
# between non-installed packages and packages installed but not vulnerable.
__pkg_match = FALSE;

function dpkgnorm(str, rls) {
    local_var str2, m;
    str2 = str_replace(find:"-lenny", string: str, replace:"lenny");
    str2 = str_replace(find:"+lenny", string: str2, replace:"lenny");
    str2 = str_replace(find:".lenny", string: str2, replace:"lenny");
    str2 = str_replace(find:"-squeeze", string: str, replace:"squeeze");
    str2 = str_replace(find:"+squeeze", string: str2, replace:"squeeze");
    str2 = str_replace(find:".squeeze", string: str2, replace:"squeeze");
    str2 = str_replace(find:"-wheezy", string: str, replace:"wheezy");
    str2 = str_replace(find:"+wheezy", string: str2, replace:"wheezy");
    str2 = str_replace(find:".wheezy", string: str2, replace:"wheezy");
    m = eregmatch(pattern:"^([0-9]:)?(.*)$", string:str2);
    if(isnull(m)) return str2;

    return(m[2]);
}

# dpkg gives us the package name and version number nicely separated out.
function isdpkgvuln(pkg, ver, rls, rls_regex) {
    local_var kbrls, rpms, pat, matches, rc, pat_a, pat_b, report;

    # Check that we have the data for this release.
    kbrls = get_kb_item("ssh/login/release");

    if(! rls_regex && kbrls != rls) {
      return NULL;
    }

    if( rls_regex ) {
      if( ! ereg(pattern:rls_regex, string:kbrls))
        return NULL;
    }

    rpms = get_kb_item("ssh/login/packages");
    if(!rpms) return NULL;
    pat = string("ii  (", pkg, ") +([0-9]:)?([^ ]+)");
    matches = eregmatch(pattern:pat, string:rpms);
    if(isnull(matches)) {
	return NULL;
    }

    __pkg_match = TRUE; # Package was installed.

    # Normalize our two strings for known idiosyncrasies
    pat_a = dpkgnorm(str:matches[3], rls:rls);
    pat_b = dpkgnorm(str:ver, rls:rls);
    rc = revcomp(a:pat_a, b:pat_b);
    if(rc<0) {
	report = "Package " + pkg + " version " +
		matches[3] + ' is installed which is known to be vulnerable.\n';
	return report;
    }
    return NULL;
}
