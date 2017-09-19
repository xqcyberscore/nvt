###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_15ad4721e3_mimedefang_fc25.nasl 7156 2017-09-18 05:28:25Z cfischer $
#
# Fedora Update for mimedefang FEDORA-2017-15ad4721e3
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.873367");
  script_version("$Revision: 7156 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 07:28:25 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-14 07:41:45 +0200 (Thu, 14 Sep 2017)");
  script_cve_id("CVE-2017-14102");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mimedefang FEDORA-2017-15ad4721e3");
  script_tag(name: "summary", value: "Check the version of mimedefang");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "MIMEDefang is an e-mail filter program 
which works with Sendmail 8.12 and later. It filters all e-mail messages sent 
via SMTP. MIMEDefang splits multi-part MIME messages into their components 
and potentially deletes or modifies the various parts. It then reassembles the 
parts back into an e-mail message and sends it on its way.

There are some caveats you should be aware of before using MIMEDefang.
MIMEDefang potentially alters e-mail messages. This breaks a 'gentleman&#39 s
agreement' that mail transfer agents do not modify message bodies. This
could cause problems, for example, with encrypted or signed messages.
");
  script_tag(name: "affected", value: "mimedefang on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-15ad4721e3");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SJK3MZNCBP4ZSYMUA6UXHOV6NWLZ3IZG");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"mimedefang", rpm:"mimedefang~2.81~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
