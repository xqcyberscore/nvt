# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2004_223_01.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from the corresponding slackware advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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

include("revisions-lib.inc");
tag_insight = "New Mozilla packages are available for Slackware 9.1, 10.0, and -current
to fix a number of security issues.  Slackware 10.0 and -current were
upgraded to Mozilla 1.7.2, and Slackware 9.1 was upgraded to Mozilla 1.4.3.
As usual, new versions of Mozilla require new versions of things that link
with the Mozilla libraries, so for Slackware 10.0 and -current new versions
of epiphany, galeon, gaim, and mozilla-plugins have also been provided.
There don't appear to be epiphany and galeon versions that are compatible
with Mozilla 1.4.3 and the GNOME in Slackware 9.1, so these are not
provided and Epiphany and Galeon will be broken on Slackware 9.1 if the
new Mozilla package is installed.  Furthermore, earlier versions of
Mozilla (such as the 1.3 series) were not fixed upstream, so versions
of Slackware earlier than 9.1 will remain vulnerable to these browser
issues.  If you still use Slackware 9.0 or earlier, you may want to
consider removing Mozilla or upgrading to a newer version.

For more details on the outsanding problems, please visit
the referenced security advisory.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2004-223-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2004-223-01";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.53919");
 script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_cve_id("CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599", "CVE-2004-0763", "CVE-2004-0758", "CVE-2004-0718", "CVE-2004-0722", "CVE-2004-0757", "CVE-2004-0759", "CVE-2004-0760", "CVE-2004-0761", "CVE-2004-0762", "CVE-2004-0764", "CVE-2004-0765");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 9352 $");
 name = "Slackware Advisory SSA:2004-223-01 Mozilla  ";
 script_name(name);



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Slackware Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-slack.inc");
vuln = 0;
if(isslkpkgvuln(pkg:"mozilla", ver:"1.4.3-i486-1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.4.3-noarch-1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mozilla", ver:"1.7.2-i486-1", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.2-noarch-1", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"epiphany", ver:"1.2.7-i486-1", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"gaim", ver:"0.81-i486-1", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"galeon", ver:"1.3.17-i486-1", rls:"SLK10.0")) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
