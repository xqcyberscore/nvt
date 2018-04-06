#
#VID 495b46fd-a30f-11e1-82c9-d0df9acfd7e5
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 495b46fd-a30f-11e1-82c9-d0df9acfd7e5
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "The following package is affected: foswiki

CVE-2012-1004
Multiple cross-site scripting (XSS) vulnerabilities in UI/Register.pm
in Foswiki before 1.1.5 allow remote authenticated users with CHANGE
privileges to inject arbitrary web script or HTML via the (1) text,
(2) FirstName, (3) LastName, (4) OrganisationName, (5)
OrganisationUrl, (6) Profession, (7) Country, (8) State, (9) Address,
(10) Location, (11) Telephone, (12) VoIP, (13) InstantMessagingIM,
(14) Email, (15) HomePage, or (16) Comment parameter.  NOTE: some of
these details are obtained from third party information.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://foswiki.org/Support/SecurityAlert-CVE-2012-1004
http://www.vuxml.org/freebsd/495b46fd-a30f-11e1-82c9-d0df9acfd7e5.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71369");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
 script_cve_id("CVE-2012-1004");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)");
 script_name("FreeBSD Ports: foswiki");


 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");
vuln = 0;
txt = "";
bver = portver(pkg:"foswiki");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.5")<0) {
    txt += "Package foswiki version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
