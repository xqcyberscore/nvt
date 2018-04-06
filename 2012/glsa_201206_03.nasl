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
tag_insight = "Multiple vulnerabilities have been found in Opera, the worst of
    which allow for the execution of arbitrary code.";
tag_solution = "All Opera users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/opera-12.00.1467'
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-03
http://bugs.gentoo.org/show_bug.cgi?id=264831
http://bugs.gentoo.org/show_bug.cgi?id=283391
http://bugs.gentoo.org/show_bug.cgi?id=290862
http://bugs.gentoo.org/show_bug.cgi?id=293902
http://bugs.gentoo.org/show_bug.cgi?id=294208
http://bugs.gentoo.org/show_bug.cgi?id=294680
http://bugs.gentoo.org/show_bug.cgi?id=308069
http://bugs.gentoo.org/show_bug.cgi?id=324189
http://bugs.gentoo.org/show_bug.cgi?id=325199
http://bugs.gentoo.org/show_bug.cgi?id=326413
http://bugs.gentoo.org/show_bug.cgi?id=332449
http://bugs.gentoo.org/show_bug.cgi?id=348874
http://bugs.gentoo.org/show_bug.cgi?id=352750
http://bugs.gentoo.org/show_bug.cgi?id=367837
http://bugs.gentoo.org/show_bug.cgi?id=373289
http://bugs.gentoo.org/show_bug.cgi?id=381275
http://bugs.gentoo.org/show_bug.cgi?id=386217
http://bugs.gentoo.org/show_bug.cgi?id=387137
http://bugs.gentoo.org/show_bug.cgi?id=393395
http://bugs.gentoo.org/show_bug.cgi?id=409857
http://bugs.gentoo.org/show_bug.cgi?id=415379
http://bugs.gentoo.org/show_bug.cgi?id=421075";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201206-03.";

                                                                                
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71547");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2009-1234", "CVE-2009-2059", "CVE-2009-2063", "CVE-2009-2067", "CVE-2009-2070", "CVE-2009-3013", "CVE-2009-3044", "CVE-2009-3045", "CVE-2009-3046", "CVE-2009-3047", "CVE-2009-3048", "CVE-2009-3049", "CVE-2009-3831", "CVE-2009-4071", "CVE-2009-4072", "CVE-2010-0653", "CVE-2010-1349", "CVE-2010-1989", "CVE-2010-1993", "CVE-2010-2121", "CVE-2010-2421", "CVE-2010-2455", "CVE-2010-2576", "CVE-2010-2658", "CVE-2010-2659", "CVE-2010-2660", "CVE-2010-2661", "CVE-2010-2662", "CVE-2010-2663", "CVE-2010-2664", "CVE-2010-2665", "CVE-2010-3019", "CVE-2010-3020", "CVE-2010-3021", "CVE-2010-4579", "CVE-2010-4580", "CVE-2010-4581", "CVE-2010-4582", "CVE-2010-4583", "CVE-2010-4584", "CVE-2010-4585", "CVE-2010-4586", "CVE-2011-0681", "CVE-2011-0682", "CVE-2011-0683", "CVE-2011-0684", "CVE-2011-0685", "CVE-2011-0686", "CVE-2011-0687", "CVE-2011-1337", "CVE-2011-1824", "CVE-2011-2609", "CVE-2011-2610", "CVE-2011-2611", "CVE-2011-2612", "CVE-2011-2613", "CVE-2011-2614", "CVE-2011-2615", "CVE-2011-2616", "CVE-2011-2617", "CVE-2011-2618", "CVE-2011-2619", "CVE-2011-2620", "CVE-2011-2621", "CVE-2011-2622", "CVE-2011-2623", "CVE-2011-2624", "CVE-2011-2625", "CVE-2011-2626", "CVE-2011-2627", "CVE-2011-2628", "CVE-2011-2629", "CVE-2011-2630", "CVE-2011-2631", "CVE-2011-2632", "CVE-2011-2633", "CVE-2011-2634", "CVE-2011-2635", "CVE-2011-2636", "CVE-2011-2637", "CVE-2011-2638", "CVE-2011-2639", "CVE-2011-2640", "CVE-2011-2641", "CVE-2011-3388", "CVE-2011-4065", "CVE-2011-4681", "CVE-2011-4682", "CVE-2011-4683", "CVE-2012-1924", "CVE-2012-1925", "CVE-2012-1926", "CVE-2012-1927", "CVE-2012-1928", "CVE-2012-1930", "CVE-2012-1931", "CVE-2012-3555", "CVE-2012-3556", "CVE-2012-3557", "CVE-2012-3558", "CVE-2012-3560", "CVE-2012-3561");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:53 -0400 (Fri, 10 Aug 2012)");
 script_name("Gentoo Security Advisory GLSA 201206-03 (Opera)");



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
if((res = ispkgvuln(pkg:"www-client/opera", unaffected: make_list("ge 12.00.1467"), vulnerable: make_list("lt 12.00.1467"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
