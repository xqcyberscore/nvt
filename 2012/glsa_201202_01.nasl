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
      # emerge --ask --oneshot --verbose '>=www-client/chromium-17.0.963.56'
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201202-01
http://bugs.gentoo.org/show_bug.cgi?id=402841
http://bugs.gentoo.org/show_bug.cgi?id=404067
http://googlechromereleases.blogspot.com/2012/02/stable-channel-update.html
http://googlechromereleases.blogspot.com/2012/02/chrome-stable-update.html";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201202-01.";

                                                                                
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71176");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-3016", "CVE-2011-3017", "CVE-2011-3018", "CVE-2011-3019", "CVE-2011-3020", "CVE-2011-3021", "CVE-2011-3022", "CVE-2011-3023", "CVE-2011-3024", "CVE-2011-3025", "CVE-2011-3027", "CVE-2011-3953", "CVE-2011-3954", "CVE-2011-3955", "CVE-2011-3956", "CVE-2011-3957", "CVE-2011-3958", "CVE-2011-3959", "CVE-2011-3960", "CVE-2011-3961", "CVE-2011-3962", "CVE-2011-3963", "CVE-2011-3964", "CVE-2011-3965", "CVE-2011-3966", "CVE-2011-3967", "CVE-2011-3968", "CVE-2011-3969", "CVE-2011-3970", "CVE-2011-3971", "CVE-2011-3972");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-03-12 11:35:34 -0400 (Mon, 12 Mar 2012)");
 script_name("Gentoo Security Advisory GLSA 201202-01 (chromium)");



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
if((res = ispkgvuln(pkg:"www-client/chromium", unaffected: make_list("ge 17.0.963.56"), vulnerable: make_list("lt 17.0.963.56"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
