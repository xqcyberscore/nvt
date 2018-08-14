###############################################################################
# OpenVAS Include File
# $Id: pkg-lib-deb.inc 10940 2018-08-13 13:14:30Z cfischer $
#
# Check if debian package is up to date
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
# $Revision: 10940 $
#
###############################################################################

# This variable is defined at inclusion time. It's declared global and is set
# to TRUE if isdpkgvuln() is called for an OS version and a package name that
# match the target's configuration. It allows the callers to distinguish
# between non-installed packages and packages installed but not vulnerable.
__pkg_match = FALSE;

# Global keys to avoid that we're repeatedly asking redis for something we already know
global_var __dpkg_ssh_release, __dpkg_ssh_pkgs;

# @brief returns the current release string of the target saved within the KB (ssh/login/release).
#
# @return a string containing the current release of the target or an empty string if no release
#         string exists in the KB.
#
# @todo Maybe move into a spearate (new) include if other pkg-lib-*.inc includes needs this as well.
#
function dpkg_get_ssh_release() {

  local_var rls;

  if( ! isnull( __dpkg_ssh_release ) ) {
    rls = string( __dpkg_ssh_release );
  } else {
    rls = string( get_kb_item( "ssh/login/release" ) );
    __dpkg_ssh_release = rls;
  }
  return rls;
}

# @brief returns the current installed packages of the target collected by gather-package-list.nasl
#        and saved within the KB (ssh/login/packages).
#
# @return a string containing the current installed packages of the target or an empty string if no
#         package list exists in the KB.
#
function dpkg_get_ssh_pkgs() {

  local_var pkgs;

  if( ! isnull( __dpkg_ssh_pkgs ) ) {
    pkgs = string( __dpkg_ssh_pkgs );
  } else {
    pkgs = string( get_kb_item( "ssh/login/packages" ) );
    __dpkg_ssh_pkgs = pkgs;
  }
  return pkgs;
}

# @brief used for string normalization that helps us with cases were even revcomp
#        can't handle things the way we would expect. For example, consider two
#        subsequent releases of cups:
#
#        1.3.8-1lenny5
#        1.3.8-1+lenny6 (yes, this really happened, but makes the results
#                        of revcomp incorrectly determine which rev is later)
#        1.3.8-1.lenny7 (ok, this didn't for this example, but did in others)
#
#        Normalization allows us to do things like change all instances to look like:
#
#        1.3.8-1lennyX
#
#        so that we can use revcomp to accurately determine which revision is the latest.
#        We're passing in rls so that we can use it if we need to - but for now,
#        the only instances causing us problems are debian lenny.
#
# @param str the string to normalize
# @param rls the release string of the target system, currently unused in this function
#
# @return the normalized string as explained in the description or NULL if no string was
#         passed via the str parameter
#
function dpkgnorm( str, rls ) {

  local_var str, rls, str2, m;

  if( ! str ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#dpkgnorm#-#str" );
    return NULL;
  }

  str2 = str_replace( find:"-lenny", string:str, replace:"lenny" );
  str2 = str_replace( find:"+lenny", string:str2, replace:"lenny" );
  str2 = str_replace( find:".lenny", string:str2, replace:"lenny" );
  str2 = str_replace( find:"-squeeze", string:str, replace:"squeeze" );
  str2 = str_replace( find:"+squeeze", string:str2, replace:"squeeze" );
  str2 = str_replace( find:".squeeze", string:str2, replace:"squeeze" );
  str2 = str_replace( find:"-wheezy", string:str, replace:"wheezy" );
  str2 = str_replace( find:"+wheezy", string:str2, replace:"wheezy" );
  str2 = str_replace( find:".wheezy", string:str2, replace:"wheezy" );
  m = eregmatch( pattern:"^([0-9]:)?(.*)$", string:str2 );
  if( isnull( m ) ) return str2;

  return( m[2] );
}

# @brief isdpkgvuln is intended to provide a quick way to verify that a given deb
#        package, if it is installed, is vulnerable or not.
#
# @param pkg         the package name (e.g. cups from the example in dpkgnorm) to check.
# @param ver         the version of the package (e.g. 1.3.8-1+lenny6 from the example
#                    in dpkgnorm) which contains a fix for the related vulnerability.
# @param rls         a release string in a form of e.g. "DEB6.0" which needs to exactly
#                    match the collected release (set by gather-package-list.nasl) so
#                    that the vulnerability is checked. rls_regex has priority over rls.
# @param rls_regex   a release regex in a form of e.g. "DEB7\.[0-9]+" which needs to
#                    match the collected release (set by gather-package-list.nasl) so
#                    that the vulnerability is checked. rls_regex has priority over rls.
# @param remove_arch if set to TRUE an possible architecture string will be removed from
#                    the package name (e.g. cups:amd64). Currently only removes amd64
#                    and i386.
#
# @return NULL if a package is not installed or is installed but up to date, a string
#         containing a report about found package and the current installed version of
#         it if it is installed and vulnerable.
#
function isdpkgvuln( pkg, ver, rls, rls_regex, remove_arch ) {

  local_var kbrls, pkgs, pat, matches, rc, pat_a, pat_b, report, remove_arch;

  if( ! pkg ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#isdpkgvuln#-#pkg" );
    return NULL;
  }

  if( ! ver ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#isdpkgvuln#-#ver" );
    return NULL;
  }

  if( ! rls && ! rls_regex ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#isdpkgvuln#-#rls/rls_regex" );
    return NULL;
  }

  # Check that we have the data for this release.
  kbrls = dpkg_get_ssh_release();
  if( ! rls_regex && kbrls != rls ) {
    return NULL;
  }

  if( rls_regex ) {
    if( ! ereg( pattern:rls_regex, string:kbrls ) )
      return NULL;
  }

  pkgs = dpkg_get_ssh_pkgs();
  if( ! pkgs ) return NULL;

  if( remove_arch ) {
    # TBD: What about other ARCH variants like arm?
    # TODO: Consider moving to dpkgnorm
    pkgs = ereg_replace( pattern:":i386", replace:"", string:pkgs );
    pkgs = ereg_replace( pattern:":amd64", replace:"", string:pkgs );
  }

  pat = string("ii  (", pkg, ") +([0-9]:)?([^ ]+)");
  matches = eregmatch( pattern:pat, string:pkgs );
  if( isnull( matches ) ) {
    return NULL;
  }

  __pkg_match = TRUE; # Package was installed.

  # Normalize our two strings for known idiosyncrasies
  pat_a = dpkgnorm( str:matches[3], rls:rls );
  pat_b = dpkgnorm( str:ver, rls:rls );
  rc = revcomp( a:pat_a, b:pat_b );
  if( rc < 0 ) {
    report  = 'Vulnerable package: ' + pkg + '\n';
    report += 'Installed version:  ' + matches[3] + '\n';
    report += 'Fixed version:      ' + ver + '\n\n';
    return report;
  }
  return NULL;
}
