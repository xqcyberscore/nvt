###############################################################################
# OpenVAS Include File
# $Id: pkg-lib-hpux.inc 10242 2018-06-19 05:45:15Z cfischer $
#
# Check if HP-UX packages are up to date
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 10242 $
#
###############################################################################

# This variable is defined at inclusion time. It's declared global and is set
# to True if ishpuxpkgvuln() is called for an OS version and a package name that
# match the target's configuration. It allows the callers to distinguish
# between non-installed packages and packages installed but not vulnerable.
__pkg_match = FALSE;

#
# ishpuxpkgvuln is intended to provide a quick way to verify that
# a given package, is installed and is vulnerable or not.
# The function ishpuxpkgvuln returns 0 if it is not installed or
# is installed and up to date, and returns 1 if it is installed
# but vulnerable
#

function ishpuxpkgvuln(pkg, revision, patch_list, rls) {

  local_var kbrls, rpms, pat, matches, rc, report;

  # Check that we have the data for this release.
  kbrls = get_kb_item("ssh/login/release");
  if(kbrls!=rls) {
    return NULL;
  }

  pkgs_rev = get_kb_item("ssh/login/hp_pkgrev");
  inst_rev = eregmatch(pattern:pkg + "(	+)?([a-zA-Z0-9.]+) ", string:chomp(pkgs_rev));
  if(isnull(inst_rev)) {
    return NULL;
  }

  __pkg_match = TRUE;

  if(patch_list != NULL) {
    patches = get_kb_item("ssh/login/hp_pkgsupersedes");
    foreach patch (patch_list) {
      if(patch >!< patches) {
        return "";
      }
    }
    return NULL;
  }

  rc = revcomp(a:inst_rev[2], b:revision);

  if(rc < 0) {
    report = 'Package ' + pkg + ' version ' + inst_rev[2] + ' is installed which is known to be vulnerable.\n';
    return report;
  }
  return NULL;
}