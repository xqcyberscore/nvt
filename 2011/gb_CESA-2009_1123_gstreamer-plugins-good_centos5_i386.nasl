###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gstreamer-plugins-good CESA-2009:1123 centos5 i386
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
tag_insight = "GStreamer is a streaming media framework, based on graphs of filters which
  operate on media data. GStreamer Good Plug-ins is a collection of
  well-supported, good quality GStreamer plug-ins.

  Multiple integer overflow flaws, that could lead to a buffer overflow, were
  found in the GStreamer Good Plug-ins PNG decoding handler. An attacker
  could create a specially-crafted PNG file that would cause an application
  using the GStreamer Good Plug-ins library to crash or, potentially, execute
  arbitrary code as the user running the application when parsed.
  (CVE-2009-1932)
  
  All users of gstreamer-plugins-good are advised to upgrade to these updated
  packages, which contain a backported patch to correct these issues. After
  installing the update, all applications using GStreamer Good Plug-ins (such
  as some media playing applications) must be restarted for the changes to
  take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "gstreamer-plugins-good on CentOS 5";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2009-June/016005.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880798");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2009:1123");
  script_cve_id("CVE-2009-1932");
  script_name("CentOS Update for gstreamer-plugins-good CESA-2009:1123 centos5 i386");

  script_tag(name:"summary", value:"Check for the Version of gstreamer-plugins-good");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-good", rpm:"gstreamer-plugins-good~0.10.9~1.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-good-devel", rpm:"gstreamer-plugins-good-devel~0.10.9~1.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
