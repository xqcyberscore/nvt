#
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
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
tag_insight = "Multiple vulnerabilities were found in OpenSSL, allowing for the
    execution of arbitrary code and other attacks.";
tag_solution = "All OpenSSL users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-1.0.0e'
    

NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since September 17, 2011. It is likely that your system is
      already no longer affected by most of these issues.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-01
http://bugs.gentoo.org/show_bug.cgi?id=303739
http://bugs.gentoo.org/show_bug.cgi?id=308011
http://bugs.gentoo.org/show_bug.cgi?id=322575
http://bugs.gentoo.org/show_bug.cgi?id=332027
http://bugs.gentoo.org/show_bug.cgi?id=345767
http://bugs.gentoo.org/show_bug.cgi?id=347623
http://bugs.gentoo.org/show_bug.cgi?id=354139
http://bugs.gentoo.org/show_bug.cgi?id=382069";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201110-01.";

                                                                                
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70764");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2009-3245", "CVE-2009-4355", "CVE-2010-0433", "CVE-2010-0740", "CVE-2010-0742", "CVE-2010-1633", "CVE-2010-2939", "CVE-2010-3864", "CVE-2010-4180", "CVE-2010-4252", "CVE-2011-0014", "CVE-2011-3207", "CVE-2011-3210");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-12 10:04:38 -0500 (Sun, 12 Feb 2012)");
 script_name("Gentoo Security Advisory GLSA 201110-01 (openssl)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
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

include("pkg-lib-gentoo.inc");
res = "";
report = "";
if((res = ispkgvuln(pkg:"dev-libs/openssl", unaffected: make_list("ge 1.0.0e", "rge 0.9.8r"), vulnerable: make_list("lt 1.0.0e"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
