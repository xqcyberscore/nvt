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
tag_insight = "Multiple vulnerabilities have been reported in Chromium, some of
    which may allow execution of arbitrary code.";
tag_solution = "All Chromium users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/chromium-21.0.1180.57'
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201208-03
http://bugs.gentoo.org/show_bug.cgi?id=423719
http://bugs.gentoo.org/show_bug.cgi?id=426204
http://bugs.gentoo.org/show_bug.cgi?id=429174
http://googlechromereleases.blogspot.com/2012/06/stable-channel-update_26.html
http://googlechromereleases.blogspot.com/2012/07/stable-channel-update.html
http://googlechromereleases.blogspot.com/2012/07/stable-channel-release.html";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201208-03.";

                                                                                
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71853");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-2815", "CVE-2012-2817", "CVE-2012-2818", "CVE-2012-2819", "CVE-2012-2820", "CVE-2012-2821", "CVE-2012-2823", "CVE-2012-2824", "CVE-2012-2825", "CVE-2012-2826", "CVE-2012-2829", "CVE-2012-2830", "CVE-2012-2831", "CVE-2012-2834", "CVE-2012-2842", "CVE-2012-2843", "CVE-2012-2846", "CVE-2012-2847", "CVE-2012-2848", "CVE-2012-2849", "CVE-2012-2853", "CVE-2012-2854", "CVE-2012-2857", "CVE-2012-2858", "CVE-2012-2859", "CVE-2012-2860");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-30 11:34:52 -0400 (Thu, 30 Aug 2012)");
 script_name("Gentoo Security Advisory GLSA 201208-03 (chromium)");



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
if((res = ispkgvuln(pkg:"www-client/chromium", unaffected: make_list("ge 21.0.1180.57"), vulnerable: make_list("lt 21.0.1180.57"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
