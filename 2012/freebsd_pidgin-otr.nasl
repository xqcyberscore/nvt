#
#VID aa71daaa-9f8c-11e1-bd0a-0082a0c18826
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID aa71daaa-9f8c-11e1-bd0a-0082a0c18826
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
tag_insight = "The following package is affected: pidgin-otr

CVE-2012-2369
Format string vulnerability in the log_message_cb function in
otr-plugin.c in the Off-the-Record Messaging (OTR) pidgin-otr plugin
before 3.2.1 for Pidgin might allow remote attackers to execute
arbitrary code via format string specifiers in data that generates a
log message.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.cypherpunks.ca/otr/
http://www.vuxml.org/freebsd/aa71daaa-9f8c-11e1-bd0a-0082a0c18826.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71372");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-2369");
 script_version("$Revision: 8649 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
 script_tag(name:"creation_date", value:"2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)");
 script_name("FreeBSD Ports: pidgin-otr");


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
bver = portver(pkg:"pidgin-otr");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.1")<0) {
    txt += "Package pidgin-otr version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
