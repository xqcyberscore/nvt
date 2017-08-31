###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for gstreamer-plugins-bad-free RHSA-2016:2974-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871732");
  script_version("$Revision: 6690 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:51:07 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-12-22 05:44:49 +0100 (Thu, 22 Dec 2016)");
  script_cve_id("CVE-2016-9445", "CVE-2016-9447");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for gstreamer-plugins-bad-free RHSA-2016:2974-01");
  script_tag(name: "summary", value: "Check the version of gstreamer-plugins-bad-free");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "GStreamer is a streaming media framework
based on graphs of filters which operate on media data. The
gstreamer-plugins-bad-free package contains a collection of plug-ins for GStreamer.

Security Fix(es):

* An integer overflow flaw, leading to a heap-based buffer overflow, was
found in GStreamer's VMware VMnc video file format decoding plug-in. A
remote attacker could use this flaw to cause an application using GStreamer
to crash or, potentially, execute arbitrary code with the privileges of the
user running the application. (CVE-2016-9445)

* A memory corruption flaw was found in GStreamer's Nintendo NSF music file
format decoding plug-in. A remote attacker could use this flaw to cause an
application using GStreamer to crash or, potentially, execute arbitrary
code with the privileges of the user running the application.
(CVE-2016-9447)

Note: This updates removes the vulnerable Nintendo NSF plug-in.");
  script_tag(name: "affected", value: "gstreamer-plugins-bad-free on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2016:2974-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2016-December/msg00026.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-bad-free", rpm:"gstreamer-plugins-bad-free~0.10.19~5.el6_8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-bad-free-debuginfo", rpm:"gstreamer-plugins-bad-free-debuginfo~0.10.19~5.el6_8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
