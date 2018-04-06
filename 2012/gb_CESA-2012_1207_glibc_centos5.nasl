###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for glibc CESA-2012:1207 centos5 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

include("revisions-lib.inc");
tag_insight = "The glibc packages provide the standard C and standard math libraries used
  by multiple programs on the system. Without these libraries, the Linux
  system cannot function properly.

  Multiple integer overflow flaws, leading to stack-based buffer overflows,
  were found in glibc's functions for converting a string to a numeric
  representation (strtod(), strtof(), and strtold()). If an application used
  such a function on attacker controlled input, it could cause the
  application to crash or, potentially, execute arbitrary code.
  (CVE-2012-3480)
  
  This update also fixes the following bug:
  
  * Previously, logic errors in various mathematical functions, including
  exp, exp2, expf, exp2f, pow, sin, tan, and rint, caused inconsistent
  results when the functions were used with the non-default rounding mode.
  This could also cause applications to crash in some cases. With this
  update, the functions now give correct results across the four different
  rounding modes. (BZ#839411)
  
  All users of glibc are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.";

tag_affected = "glibc on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-August/018826.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881476");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-08-28 10:26:19 +0530 (Tue, 28 Aug 2012)");
  script_cve_id("CVE-2012-3480");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2012:1207");
  script_name("CentOS Update for glibc CESA-2012:1207 centos5 ");

  script_tag(name: "summary" , value: "Check for the Version of glibc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.5~81.el5_8.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.5~81.el5_8.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.5~81.el5_8.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.5~81.el5_8.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.5~81.el5_8.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.5~81.el5_8.7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
