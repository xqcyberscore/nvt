###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for elinks CESA-2009:1471 centos4 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "ELinks is a text-based Web browser. ELinks does not display any images, but
  it does support frames, tables, and most other HTML tags.

  An off-by-one buffer overflow flaw was discovered in the way ELinks handled
  its internal cache of string representations for HTML special entities. A
  remote attacker could use this flaw to create a specially-crafted HTML file
  that would cause ELinks to crash or, possibly, execute arbitrary code when
  rendered. (CVE-2008-7224)
  
  It was discovered that ELinks tried to load translation files using
  relative paths. A local attacker able to trick a victim into running ELinks
  in a folder containing specially-crafted translation files could use this
  flaw to confuse the victim via incorrect translations, or cause ELinks to
  crash and possibly execute arbitrary code via embedded formatting sequences
  in translated messages. (CVE-2007-2027)
  
  All ELinks users are advised to upgrade to this updated package, which
  contains backported patches to resolve these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "elinks on CentOS 4";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2009-October/016177.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880923");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "CESA", value: "2009:1471");
  script_cve_id("CVE-2007-2027", "CVE-2008-7224");
  script_name("CentOS Update for elinks CESA-2009:1471 centos4 i386");

  script_tag(name:"summary", value:"Check for the Version of elinks");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"elinks", rpm:"elinks~0.9.2~4.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
