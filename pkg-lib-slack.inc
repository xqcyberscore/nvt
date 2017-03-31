# OpenVAS Vulnerability Test include file
# $Id$
# Description: Check if slackware package is up to date
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
# isslkpkgvuln takes the packagename (e.g.sendmail-cf), a version
# number (e.g. 8.12.11) and a release (e.g. SLK10.0) and then
# checks the knowledgebase to see if a version of the package
# older than version was listed in /var/log/packages on the Slackeware
# system.  The listing is held in kb "ssh/login/slackpack"
# Returns 1 if vulnerable version is installed, 0 otherwise.

function isslkpkgvuln(pkg, ver, rls) {
    local_var kbrls, pkgs, narrowed, list, rc;
    # Check that we have the data for this release.
    kbrls = get_kb_item("ssh/login/release");
    if(kbrls!=rls) {
	return(0);
    }
    pkgs = get_kb_item("ssh/login/slackpack");
    if(!pkgs) return(0);
    narrowed = egrep(pattern:"^" + pkg + "-[0-9]", string:pkgs);
    if(!narrowed) return(0);
    list = split(narrowed, sep:'\n', keep:0);

    __pkg_match = TRUE; # Package was installed.
    
    foreach package (list) {
	# security_message(0, data: "Comparing "+package+" against "+pkg+"-"+ver);
	rc = revcomp(a:package, b:pkg + "-" + ver);
	if(rc<0) {
	    security_message(0, data: "Package " + package + 
		    " is installed which is known to be vulnerable.");
	    return(1);
	}
    }

    return(0);
}
