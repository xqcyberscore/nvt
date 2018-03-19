###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_ee417c4b28_suricata_fc27.nasl 9119 2018-03-16 15:21:49Z cfischer $
#
# Fedora Update for suricata FEDORA-2018-ee417c4b28
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.874142");
  script_version("$Revision: 9119 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-16 16:21:49 +0100 (Fri, 16 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-02-24 09:08:19 +0100 (Sat, 24 Feb 2018)");
  script_cve_id("CVE-2018-6794");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for suricata FEDORA-2018-ee417c4b28");
  script_tag(name: "summary", value: "Check the version of suricata");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The Suricata Engine is an Open Source 
Next Generation Intrusion Detection and Prevention Engine. This engine is not 
intended to just replace or emulate the existing tools in the industry, but
will bring new ideas and technologies to the field. This new Engine supports 
Multi-threading, Automatic Protocol Detection (IP, TCP, UDP, ICMP, HTTP, TLS, 
FTP and SMB! ), Gzip Decompression, Fast IP Matching, and GeoIP identification.
");
  script_tag(name: "affected", value: "suricata on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-ee417c4b28");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MMJ7GBVHN2GV3KAIBBRSZU2JQA5X4ZPO");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"suricata", rpm:"suricata~4.0.4~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
